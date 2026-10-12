/* Il submitter conserva logout=yes; form.submit() lo perderebbe.
   Questo file viene caricato solo dopo la verifica del token nel renderer. */
const form = document.getElementById('op.logoutForm');
const submitter = document.getElementById('logout-confirm');
if (form instanceof HTMLFormElement && submitter instanceof HTMLButtonElement) {
  form.requestSubmit(submitter);
}
