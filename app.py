import os, re, secrets, random, string
from datetime import datetime, date, timedelta
from collections import defaultdict
from functools import wraps

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, abort)
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

# ══════════════════════════════════════════════════════
# APP SETUP
# ══════════════════════════════════════════════════════
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Mail
app.config.update(
    MAIL_SERVER          = os.environ.get('MAIL_SERVER',   'smtp.gmail.com'),
    MAIL_PORT            = int(os.environ.get('MAIL_PORT', 587)),
    MAIL_USE_TLS         = True,
    MAIL_USERNAME        = os.environ.get('MAIL_USERNAME', ''),
    MAIL_PASSWORD        = os.environ.get('MAIL_PASSWORD', ''),
    MAIL_DEFAULT_SENDER  = os.environ.get('MAIL_USERNAME', 'noreply@pourlog.app'),
)
mail = Mail(app)

# Rate limiter
limiter = Limiter(get_remote_address, app=app, default_limits=[],
                  storage_uri="memory://")

# DB
DATA_DIR = '/data' if os.path.isdir('/data') else os.path.dirname(__file__)
DB       = os.path.join(DATA_DIR, 'pegtrack.db')

CALORIE_MAP  = {'Beer':43,'Wine':83,'Spirits':220,'Cocktail':170,'Cider':44,'Other':60}
OTP_EXPIRY   = 5          # minutes
OTP_MAX_TRIES = 5         # max wrong attempts before lockout

# Dev mode — no real email/SMS credentials set
_mail_ready   = bool(os.environ.get('MAIL_USERNAME') and os.environ.get('MAIL_PASSWORD')
                     and '@' in os.environ.get('MAIL_USERNAME',''))
_twilio_ready = bool(os.environ.get('TWILIO_SID'))
DEV_MODE      = not (_mail_ready or _twilio_ready)

# ══════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            username       TEXT UNIQUE NOT NULL,
            email          TEXT UNIQUE NOT NULL,
            phone          TEXT UNIQUE NOT NULL,
            password_hash  TEXT NOT NULL,
            gender         TEXT DEFAULT 'male',
            weight_kg      REAL DEFAULT 70,
            monthly_limit  REAL DEFAULT 56,
            is_verified    INTEGER DEFAULT 0,
            created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS otps (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier   TEXT NOT NULL,
            purpose      TEXT NOT NULL,
            code         TEXT NOT NULL,
            attempts     INTEGER DEFAULT 0,
            expires_at   TIMESTAMP NOT NULL,
            used         INTEGER DEFAULT 0,
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS drinks (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            date       TEXT NOT NULL,
            type       TEXT NOT NULL,
            name       TEXT NOT NULL,
            ml         REAL NOT NULL,
            abv        REAL NOT NULL,
            cost       REAL DEFAULT 0,
            units      REAL NOT NULL,
            calories   INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        # Safe migrations for existing DBs
        for sql in [
            "ALTER TABLE users ADD COLUMN username TEXT",
            "ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN password_hash TEXT",
            "ALTER TABLE otps ADD COLUMN attempts INTEGER DEFAULT 0",
        ]:
            try: conn.execute(sql)
            except: pass
        conn.commit()

# ══════════════════════════════════════════════════════
# VALIDATION HELPERS
# ══════════════════════════════════════════════════════
def is_valid_email(s):
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', s))

def is_valid_phone(s):
    return bool(re.match(r'^\+?[0-9]{7,15}$', s.replace(' ','')))

def is_strong_password(p):
    return (len(p) >= 8 and
            re.search(r'[A-Z]', p) and
            re.search(r'[a-z]', p) and
            re.search(r'\d', p))

def sanitize(s):
    """Basic XSS prevention — strip dangerous chars."""
    return re.sub(r'[<>"\'%;()&+]', '', str(s)).strip()

# ══════════════════════════════════════════════════════
# OTP HELPERS
# ══════════════════════════════════════════════════════
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def create_otp(identifier, purpose):
    code    = generate_otp()
    expires = (datetime.now() + timedelta(minutes=OTP_EXPIRY)).isoformat()
    with get_db() as conn:
        conn.execute("UPDATE otps SET used=1 WHERE identifier=? AND purpose=? AND used=0",
                     (identifier, purpose))
        conn.execute("INSERT INTO otps (identifier,purpose,code,expires_at) VALUES (?,?,?,?)",
                     (identifier, purpose, code, expires))
        conn.commit()
    return code

def validate_otp(identifier, code, purpose):
    """Returns 'ok', 'expired', 'invalid', or 'locked'."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM otps WHERE identifier=? AND purpose=? AND used=0 "
            "ORDER BY id DESC LIMIT 1", (identifier, purpose)
        ).fetchone()
        if not row:
            return 'invalid'
        if row['attempts'] >= OTP_MAX_TRIES:
            return 'locked'
        if datetime.fromisoformat(row['expires_at']) < datetime.now():
            conn.execute("UPDATE otps SET used=1 WHERE id=?", (row['id'],))
            conn.commit()
            return 'expired'
        if row['code'] != code.strip():
            conn.execute("UPDATE otps SET attempts=attempts+1 WHERE id=?", (row['id'],))
            conn.commit()
            remaining = OTP_MAX_TRIES - row['attempts'] - 1
            return f'invalid:{remaining}'
        conn.execute("UPDATE otps SET used=1 WHERE id=?", (row['id'],))
        conn.commit()
        return 'ok'

def send_otp(identifier, purpose):
    """Generate OTP and dispatch via email, SMS, or dev console."""
    code = create_otp(identifier, purpose)
    label = {'login':'Sign In','register':'Verify Account','reset':'Reset Password'}.get(purpose,'OTP')

    if DEV_MODE:
        print(f"\n{'='*40}\n🔑 DEV OTP [{purpose}] for {identifier}: {code}\n{'='*40}\n")
        return True, code

    if is_valid_email(identifier):
        return _send_email_otp(identifier, code, label), code
    else:
        return _send_sms_otp(identifier, code), code

def _send_email_otp(email, code, label):
    try:
        msg = Message(
            subject=f'PourLog — {code} is your {label} code',
            recipients=[email],
            html=f"""
<div style="font-family:sans-serif;max-width:460px;margin:0 auto;background:#0e0e12;color:#f0f0f5;border-radius:16px;overflow:hidden">
  <div style="background:#e8a020;padding:20px 28px;display:flex;align-items:center;gap:10px">
    <span style="font-size:24px;font-weight:900;color:#0e0e12;letter-spacing:-1px">◈ PourLog</span>
  </div>
  <div style="padding:32px 28px">
    <h2 style="margin:0 0 8px;font-size:22px;color:#f0f0f5">{label}</h2>
    <p style="color:#8a8a9a;margin:0 0 28px;font-size:15px;line-height:1.6">
      Use the code below to continue. It expires in <strong style="color:#f0f0f5">{OTP_EXPIRY} minutes</strong>.
    </p>
    <div style="background:#16161c;border:1.5px solid #e8a020;border-radius:12px;padding:24px;text-align:center;margin-bottom:28px">
      <span style="font-size:44px;font-weight:900;letter-spacing:14px;color:#e8a020;font-family:monospace">{code}</span>
    </div>
    <p style="color:#5a5a6a;font-size:13px;margin:0">
      Didn't request this? Ignore this email — your account is safe.
    </p>
  </div>
</div>"""
        )
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Email OTP failed: {e}")
        return False

def _send_sms_otp(phone, code):
    sid   = os.environ.get('TWILIO_SID')
    token = os.environ.get('TWILIO_TOKEN')
    from_ = os.environ.get('TWILIO_FROM')
    if not (sid and token and from_):
        print(f"\n📱 DEV SMS OTP for {phone}: {code}\n")
        return True
    try:
        from twilio.rest import Client
        to = phone if phone.startswith('+') else f'+91{phone}'
        Client(sid, token).messages.create(
            body=f'Your PourLog OTP is {code}. Valid {OTP_EXPIRY} minutes. Do not share.',
            from_=from_, to=to
        )
        return True
    except Exception as e:
        app.logger.error(f"SMS OTP failed: {e}")
        return False

# ══════════════════════════════════════════════════════
# AUTH DECORATORS & SESSION
# ══════════════════════════════════════════════════════
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please sign in to continue.', 'info')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if 'user_id' not in session: return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()

# ══════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════

# ── LOGIN ──────────────────────────────────────────────
@app.route('/login', methods=['GET','POST'])
@limiter.limit("20 per minute")
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = sanitize(request.form.get('username',''))
        password = request.form.get('password','')

        if not username or not password:
            flash('Please enter username and password.', 'error')
            return render_template('login.html')

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username=? OR email=?",
                (username, username)
            ).fetchone()

        if not user or not check_password_hash(user['password_hash'], password):
            flash('Incorrect username or password.', 'error')
            return render_template('login.html')

        if not user['is_verified']:
            session['pending_verify_id']    = user['id']
            session['pending_verify_phone'] = user['phone']
            ok, code = send_otp(user['phone'], 'register')
            if DEV_MODE: flash(f'[DEV] OTP: {code}', 'dev')
            flash('Your account is not verified yet. OTP sent to your phone.', 'info')
            return redirect(url_for('verify_otp'))

        session.permanent = True
        session['user_id']   = user['id']
        session['user_name'] = user['username']
        return redirect(url_for('dashboard'))

    return render_template('login.html')


# ── REGISTER ───────────────────────────────────────────
@app.route('/register', methods=['GET','POST'])
@limiter.limit("10 per hour")
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = sanitize(request.form.get('username','')).lower()
        email    = sanitize(request.form.get('email','')).lower()
        phone    = sanitize(request.form.get('phone',''))
        password = request.form.get('password','')
        confirm  = request.form.get('confirm_password','')
        gender   = request.form.get('gender','male')
        weight   = float(request.form.get('weight_kg', 70) or 70)
        limit    = float(request.form.get('monthly_limit', 56) or 56)

        errors = []
        if len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if not is_valid_email(email):
            errors.append('Enter a valid email address.')
        if not is_valid_phone(phone):
            errors.append('Enter a valid phone number (7–15 digits).')
        if not is_strong_password(password):
            errors.append('Password must be 8+ characters with uppercase, lowercase and a number.')
        if password != confirm:
            errors.append('Passwords do not match.')

        if errors:
            for e in errors: flash(e, 'error')
            return render_template('register.html',
                                   username=username, email=email, phone=phone)

        pw_hash = generate_password_hash(password)
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (username,email,phone,password_hash,gender,weight_kg,monthly_limit,is_verified) "
                    "VALUES (?,?,?,?,?,?,?,0)",
                    (username, email, phone, pw_hash, gender, weight, limit)
                )
                conn.commit()
                user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        except sqlite3.IntegrityError as e:
            msg = str(e)
            if 'username' in msg: flash('Username already taken.', 'error')
            elif 'email'  in msg: flash('Email already registered.', 'error')
            elif 'phone'  in msg: flash('Phone number already registered.', 'error')
            else: flash('Account already exists.', 'error')
            return render_template('register.html',
                                   username=username, email=email, phone=phone)

        ok, code = send_otp(phone, 'register')
        session['pending_verify_id']    = user['id']
        session['pending_verify_phone'] = phone
        if DEV_MODE: flash(f'[DEV] OTP: {code}', 'dev')
        flash(f'Account created! OTP sent to {phone}. Enter it to activate your account.', 'success')
        return redirect(url_for('verify_otp'))

    return render_template('register.html')


# ── VERIFY OTP ─────────────────────────────────────────
@app.route('/verify', methods=['GET','POST'])
@limiter.limit("10 per minute")
def verify_otp():
    pending_id    = session.get('pending_verify_id')
    pending_phone = session.get('pending_verify_phone')
    purpose       = session.get('otp_purpose', 'register')

    if not pending_id and not pending_phone:
        return redirect(url_for('login'))

    identifier = session.get('reset_identifier') or pending_phone

    if request.method == 'POST':
        code   = request.form.get('otp','').strip().replace(' ','')
        result = validate_otp(identifier, code, purpose)

        if result == 'ok':
            if purpose == 'reset':
                session['reset_verified']    = True
                session['reset_identifier']  = identifier
                session.pop('otp_purpose', None)
                return redirect(url_for('reset_password'))

            # Activate account
            with get_db() as conn:
                conn.execute("UPDATE users SET is_verified=1 WHERE id=?", (pending_id,))
                conn.commit()
                user = conn.execute("SELECT * FROM users WHERE id=?", (pending_id,)).fetchone()

            session.pop('pending_verify_id',    None)
            session.pop('pending_verify_phone', None)
            session['user_id']   = user['id']
            session['user_name'] = user['username']
            flash('Account verified! Welcome to PourLog 🎉', 'success')
            return redirect(url_for('dashboard'))

        elif result == 'expired':
            flash('OTP has expired. Please request a new one.', 'error')
        elif result == 'locked':
            flash(f'Too many wrong attempts. Request a new OTP.', 'error')
        else:
            remaining = result.split(':')[1] if ':' in result else '?'
            flash(f'Incorrect OTP. {remaining} attempt(s) left.', 'error')

        return render_template('verify_otp.html', identifier=identifier, purpose=purpose)

    return render_template('verify_otp.html', identifier=identifier, purpose=purpose)


@app.route('/resend-otp', methods=['POST'])
@limiter.limit("5 per 10 minutes")
def resend_otp():
    identifier = (session.get('reset_identifier') or
                  session.get('pending_verify_phone'))
    purpose    = session.get('otp_purpose', 'register')
    if identifier:
        ok, code = send_otp(identifier, purpose)
        flash('New OTP sent!', 'success')
        if DEV_MODE: flash(f'[DEV] OTP: {code}', 'dev')
    return redirect(url_for('verify_otp'))


# ── FORGOT PASSWORD ────────────────────────────────────
@app.route('/forgot', methods=['GET','POST'])
@limiter.limit("5 per 10 minutes")
def forgot():
    if request.method == 'POST':
        identifier = sanitize(request.form.get('identifier','')).strip()
        with get_db() as conn:
            if is_valid_email(identifier):
                user = conn.execute("SELECT * FROM users WHERE email=?", (identifier,)).fetchone()
            else:
                user = conn.execute("SELECT * FROM users WHERE phone=?", (identifier,)).fetchone()

        if not user:
            flash('No account found with that email or phone number.', 'error')
            return render_template('forgot.html')

        ok, code = send_otp(identifier, 'reset')
        session['reset_identifier'] = identifier
        session['otp_purpose']      = 'reset'
        session['pending_verify_id'] = user['id']
        if DEV_MODE: flash(f'[DEV] OTP: {code}', 'dev')
        flash(f'Recovery OTP sent to {identifier}.', 'success')
        return redirect(url_for('verify_otp'))

    return render_template('forgot.html')


# ── RESET PASSWORD ─────────────────────────────────────
@app.route('/reset-password', methods=['GET','POST'])
def reset_password():
    if not session.get('reset_verified'):
        flash('Please verify your OTP first.', 'error')
        return redirect(url_for('forgot'))

    if request.method == 'POST':
        password = request.form.get('password','')
        confirm  = request.form.get('confirm_password','')

        if not is_strong_password(password):
            flash('Password must be 8+ chars with uppercase, lowercase and a number.', 'error')
            return render_template('reset_password.html')
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html')

        identifier = session.get('reset_identifier')
        pw_hash    = generate_password_hash(password)
        with get_db() as conn:
            if is_valid_email(identifier):
                conn.execute("UPDATE users SET password_hash=? WHERE email=?", (pw_hash, identifier))
            else:
                conn.execute("UPDATE users SET password_hash=? WHERE phone=?", (pw_hash, identifier))
            conn.commit()

        session.pop('reset_verified',    None)
        session.pop('reset_identifier',  None)
        session.pop('pending_verify_id', None)
        flash('Password reset successfully! Please sign in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')


# ── LOGOUT ─────────────────────────────────────────────
@app.route('/logout')
def logout():
    session.clear()
    flash('Signed out successfully.', 'info')
    return redirect(url_for('login'))


# ── PROFILE ────────────────────────────────────────────
@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    user = get_current_user()
    if request.method == 'POST':
        gender = request.form.get('gender','male')
        weight = float(request.form.get('weight_kg', 70) or 70)
        limit  = float(request.form.get('monthly_limit', 56) or 56)
        with get_db() as conn:
            conn.execute("UPDATE users SET gender=?,weight_kg=?,monthly_limit=? WHERE id=?",
                         (gender, weight, limit, session['user_id']))
            conn.commit()
        flash('Profile updated!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)


# ══════════════════════════════════════════════════════
# APP HELPERS
# ══════════════════════════════════════════════════════
def calc_units(ml, abv):    return round(ml * abv / 1000, 2)
def calc_calories(ml, dt):  return round(ml * CALORIE_MAP.get(dt, 60) / 100)

def aggregate(rows):
    return {
        'units': round(sum(r['units'] for r in rows), 1),
        'ml':    int(sum(r['ml'] for r in rows)),
        'cals':  int(sum(r['calories'] for r in rows)),
        'cost':  int(sum(r['cost'] for r in rows)),
        'count': len(rows),
    }

def get_months(conn, uid):
    return [r['m'] for r in conn.execute(
        "SELECT DISTINCT substr(date,1,7) as m FROM drinks WHERE user_id=? ORDER BY m DESC",(uid,)
    ).fetchall()]

def get_years(conn, uid):
    return [r['y'] for r in conn.execute(
        "SELECT DISTINCT substr(date,1,4) as y FROM drinks WHERE user_id=? ORDER BY y DESC",(uid,)
    ).fetchall()]

def build_alert(conn, uid, monthly_limit):
    month = date.today().isoformat()[:7]
    rows  = conn.execute("SELECT units FROM drinks WHERE user_id=? AND date LIKE ?",
                         (uid, f"{month}%")).fetchall()
    total = round(sum(r['units'] for r in rows), 1)
    pct   = total / monthly_limit * 100 if monthly_limit else 0
    if   pct >= 100: level,msg = 'danger',  f"Monthly limit reached! {total:.1f}/{monthly_limit:.0f} units"
    elif pct >= 80:  level,msg = 'warning', f"Approaching limit — {total:.1f}/{monthly_limit:.0f} units ({pct:.0f}%)"
    elif pct >= 60:  level,msg = 'info',    f"Past halfway — {total:.1f}/{monthly_limit:.0f} units"
    else: return None
    return {'level':level,'msg':msg,'total':total,'limit':monthly_limit,'pct':min(pct,100)}


# ══════════════════════════════════════════════════════
# MAIN APP ROUTES
# ══════════════════════════════════════════════════════
@app.route('/')
@login_required
def dashboard():
    uid = session['user_id']
    today = date.today().isoformat()
    cur_month = today[:7]; cur_year = today[:4]
    mode      = request.args.get('mode','month')
    sel_month = request.args.get('month', cur_month)
    sel_year  = request.args.get('year',  cur_year)

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
        pattern      = f"{sel_year}%" if mode=='year' else f"{sel_month}%"
        period_label = sel_year if mode=='year' else datetime.strptime(sel_month,'%Y-%m').strftime('%B %Y')
        period_rows  = conn.execute("SELECT * FROM drinks WHERE user_id=? AND date LIKE ? ORDER BY date DESC",(uid,pattern)).fetchall()
        today_rows   = conn.execute("SELECT * FROM drinks WHERE user_id=? AND date=? ORDER BY created_at DESC",(uid,today)).fetchall()
        stats        = aggregate(period_rows); today_stats = aggregate(today_rows)
        by_type = defaultdict(lambda:{'units':0,'ml':0})
        for r in period_rows: by_type[r['type']]['units']+=r['units']; by_type[r['type']]['ml']+=r['ml']
        by_type          = dict(sorted(by_type.items(), key=lambda x:-x[1]['units']))
        available_months = get_months(conn, uid)
        available_years  = get_years(conn, uid)
        alert            = build_alert(conn, uid, user['monthly_limit'])

    return render_template('dashboard.html',
        stats=stats, by_type=by_type, today_stats=today_stats,
        period_label=period_label, mode=mode,
        sel_month=sel_month, sel_year=sel_year,
        available_months=available_months, available_years=available_years,
        cur_month=cur_month, cur_year=cur_year, alert=alert, user=user)


@app.route('/log', methods=['GET','POST'])
@login_required
def log_drink():
    uid = session['user_id']
    if request.method == 'POST':
        dtype    = request.form['type']
        name     = sanitize(request.form.get('name','') or dtype)
        ml       = float(request.form.get('ml',0))
        abv      = float(request.form.get('abv',0))
        cost     = float(request.form.get('cost',0) or 0)
        log_date = request.form.get('date') or date.today().isoformat()
        with get_db() as conn:
            conn.execute(
                "INSERT INTO drinks (user_id,date,type,name,ml,abv,cost,units,calories) VALUES (?,?,?,?,?,?,?,?,?)",
                (uid,log_date,dtype,name,ml,abv,cost,calc_units(ml,abv),calc_calories(ml,dtype))
            )
            conn.commit()
        return redirect(url_for('dashboard'))

    today = date.today().isoformat()
    with get_db() as conn:
        today_rows = conn.execute("SELECT * FROM drinks WHERE user_id=? AND date=? ORDER BY created_at DESC",(uid,today)).fetchall()
        user       = conn.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
        alert      = build_alert(conn, uid, user['monthly_limit'])
    return render_template('log.html', today_rows=today_rows, today=today, alert=alert, user=user)


@app.route('/delete/<int:drink_id>', methods=['POST'])
@login_required
def delete_drink(drink_id):
    with get_db() as conn:
        conn.execute("DELETE FROM drinks WHERE id=? AND user_id=?",(drink_id,session['user_id']))
        conn.commit()
    return redirect(url_for(request.form.get('next','dashboard')))


@app.route('/history')
@login_required
def history():
    uid = session['user_id']
    cur_month = date.today().isoformat()[:7]; cur_year = date.today().isoformat()[:4]
    mode      = request.args.get('mode','month')
    sel_month = request.args.get('month', cur_month)
    sel_year  = request.args.get('year',  cur_year)

    with get_db() as conn:
        if mode=='year':  pattern,period_label = f"{sel_year}%", sel_year
        elif mode=='all': pattern,period_label = '%','All time'
        else:
            pattern      = f"{sel_month}%"
            period_label = datetime.strptime(sel_month,'%Y-%m').strftime('%B %Y')
        rows = conn.execute("SELECT * FROM drinks WHERE user_id=? AND date LIKE ? ORDER BY date DESC, created_at DESC",(uid,pattern)).fetchall()
        available_months = get_months(conn, uid)
        available_years  = get_years(conn, uid)
        user  = conn.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
        alert = build_alert(conn, uid, user['monthly_limit'])

    grouped = defaultdict(list)
    for r in rows: grouped[r['date']].append(r)
    grouped = dict(sorted(grouped.items(), reverse=True))
    return render_template('history.html',
        grouped=grouped, mode=mode, sel_month=sel_month, sel_year=sel_year,
        period_label=period_label, available_months=available_months,
        available_years=available_years, total_stats=aggregate(rows), alert=alert, user=user)


@app.route('/trends')
@login_required
def trends():
    uid      = session['user_id']
    view     = request.args.get('view','monthly')
    sel_year = request.args.get('year', date.today().isoformat()[:4])

    with get_db() as conn:
        all_rows        = conn.execute("SELECT * FROM drinks WHERE user_id=? ORDER BY date",(uid,)).fetchall()
        available_years = get_years(conn, uid)
        user  = conn.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
        alert = build_alert(conn, uid, user['monthly_limit'])

    monthly = defaultdict(lambda:{'units':0,'cost':0,'cals':0,'ml':0})
    yearly  = defaultdict(lambda:{'units':0,'cost':0,'cals':0,'ml':0})
    for r in all_rows:
        for d,k in [(monthly,r['date'][:7]),(yearly,r['date'][:4])]:
            d[k]['units']+=r['units']; d[k]['cost']+=r['cost']
            d[k]['cals']+=r['calories']; d[k]['ml']+=r['ml']

    src  = yearly if view=='yearly' else monthly
    keys = sorted(yearly.keys()) if view=='yearly' else sorted(k for k in monthly if k.startswith(sel_year))
    labels     = keys if view=='yearly' else [datetime.strptime(k,'%Y-%m').strftime('%b') for k in keys]
    units_data = [round(src[k]['units'],1) for k in keys]
    cost_data  = [int(src[k]['cost']) for k in keys]
    cal_data   = [int(src[k]['cals']) for k in keys]
    ml_data    = [int(src[k]['ml'])   for k in keys]

    period_rows    = [r for r in all_rows if r['date'][:4]==sel_year]
    type_breakdown = defaultdict(lambda:{'units':0,'ml':0})
    for r in period_rows: type_breakdown[r['type']]['units']+=r['units']; type_breakdown[r['type']]['ml']+=r['ml']

    return render_template('trends.html',
        view=view, sel_year=sel_year, available_years=available_years,
        labels=labels, units_data=units_data, cost_data=cost_data, cal_data=cal_data, ml_data=ml_data,
        year_stats=aggregate(period_rows), all_stats=aggregate(all_rows),
        type_breakdown=dict(type_breakdown), alert=alert, user=user)


@app.route('/calculator')
@login_required
def calculator():
    with get_db() as conn:
        user  = conn.execute("SELECT * FROM users WHERE id=?",(session['user_id'],)).fetchone()
        alert = build_alert(conn, session['user_id'], user['monthly_limit'])
    return render_template('calculator.html', user=user, alert=alert)


# ══════════════════════════════════════════════════════
if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
