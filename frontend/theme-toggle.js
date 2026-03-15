// Temporary theme toggle logic until script.js update
document.addEventListener('DOMContentLoaded', () => {
  const html = document.documentElement;
  const isDark = localStorage.getItem('theme') === 'dark' || (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches);
  html.classList.toggle('dark', isDark);
  localStorage.setItem('theme', isDark ? 'dark' : 'light');
});
