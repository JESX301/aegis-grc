// Dark/light theme toggle. The pre-paint setter lives inline in <head> (no FOUC);
// this only handles the click and persists the choice.
function toggleTheme() {
  var cur = document.documentElement.getAttribute('data-theme') || 'light';
  var next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('aegis-theme', next); } catch (e) { /* ignore */ }
}
