// Highlight active nav on load
document.addEventListener('DOMContentLoaded', () => {
  // Add ripple to submit button
  const btn = document.querySelector('.submit-btn');
  if (btn) {
    btn.addEventListener('click', function(e) {
      this.style.transform = 'scale(0.97)';
      setTimeout(() => this.style.transform = '', 120);
    });
  }

  // Auto-dismiss flash messages
  document.querySelectorAll('.flash').forEach(el => {
    setTimeout(() => el.remove(), 3000);
  });
});
