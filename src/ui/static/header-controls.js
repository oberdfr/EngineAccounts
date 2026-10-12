/* Account/Admin are ordinary navigation links. Profile is a native details menu. */
(() => {
  const identity = document.querySelector('[data-identity-menu]');
  if (!identity) return;
  const trigger = identity.querySelector('summary');
  const close = (restoreFocus = false) => {
    identity.open = false;
    if (restoreFocus) trigger?.focus({ preventScroll: true });
  };
  identity.addEventListener('click', (event) => {
    if (event.target.closest('a')) close();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && identity.open) {
      event.preventDefault(); close(true);
    }
  });
  document.addEventListener('pointerdown', (event) => {
    if (identity.open && !identity.contains(event.target)) close();
  });
  document.addEventListener('focusin', (event) => {
    if (identity.open && !identity.contains(event.target)) close();
  });
})();
