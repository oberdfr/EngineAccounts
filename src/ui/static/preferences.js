/* Browser-only display preference. No account, credential or API data is stored. */
(function () {
  'use strict';
  var key = 'engine-accounts:animations';
  var controls = document.querySelectorAll('[data-animation-preference]');
  var enabled = false;
  try { enabled = window.localStorage.getItem(key) === 'true'; } catch (_) { /* Storage may be unavailable. */ }
  function apply(value) {
    document.documentElement.setAttribute('data-animations', value ? 'true' : 'false');
    controls.forEach(function (control) { control.checked = value; });
  }
  apply(enabled);
  controls.forEach(function (control) {
    control.closest('label').hidden = false;
    control.addEventListener('change', function () {
      apply(control.checked);
      try { window.localStorage.setItem(key, control.checked ? 'true' : 'false'); } catch (_) { /* Current page still works. */ }
    });
  });
  window.addEventListener('storage', function (event) {
    if (event.key === key || event.key === null) apply(event.key === key && event.newValue === 'true');
  });
})();
