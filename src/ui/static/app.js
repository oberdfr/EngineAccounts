/* Engine Accounts — comportamento lato client.
 *
 * Regola CSP: questo file e' servito da /static, nessuno script inline. Quello
 * che potrebbe essere JS inline (conferma distruttiva, submit a endpoint
 * diversi) e' HTML puro: `formaction`, `required`, `confirm` come attributo.
 * Qui sotto c'e' solo WebAuthn, che il browser non permette di fare altrimenti.
 */

(function () {
  'use strict';

  function base64urlToBuffer(value) {
    var padded = value.replace(/-/g, '+').replace(/_/g, '/');
    while (padded.length % 4 !== 0) padded += '=';
    var binary = window.atob(padded);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function jsonFetch(url, options) {
    return fetch(url, Object.assign({ headers: { accept: 'application/json' } }, options));
  }

  /* ---------------------------------------------------------------- WebAuthn */
  /* Form di registrazione: il server ha gia' generato le options e le ha
   * serializzate in un <script type="application/json"> (JSON, non eseguibile). */
  function setupRegistration() {
    var node = document.querySelector('[data-webauthn="register"]');
    if (!node || !window.PublicKeyCredential) {
      var missing = document.getElementById('wa-status');
      if (missing) missing.textContent = 'Questo browser non supporta le passkey.';
      return;
    }
    var payload = document.getElementById('wa-options');
    var input = document.querySelector('input[name="webauthnResponse"]');
    var status = document.getElementById('wa-status');
    if (!payload || !input) return;

    var options;
    try {
      options = JSON.parse(payload.textContent || '{}');
    } catch (err) {
      if (status) status.textContent = 'Opzioni non valide.';
      return;
    }

    var form = node.closest('form');
    if (!form) return;
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      if (status) status.textContent = 'Segui le istruzioni del tuo dispositivo…';
      options.challenge = base64urlToBuffer(options.challenge);
      options.user.id = base64urlToBuffer(options.user.id);
      if (options.excludeCredentials) {
        options.excludeCredentials = options.excludeCredentials.map(function (c) {
          return Object.assign({}, c, { id: base64urlToBuffer(c.id) });
        });
      }
      navigator.credentials
        .create({ publicKey: options })
        .then(function (credential) {
          input.value = JSON.stringify({
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
              clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
              attestationObject: bufferToBase64url(credential.response.attestationObject),
            },
            transports: credential.response.getTransports ? credential.response.getTransports() : [],
          });
          form.submit();
        })
        .catch(function (err) {
          if (status) status.textContent = 'Operazione annullata o fallita: ' + err.name;
        });
    });
  }

  /* Form di autenticazione: avviano al caricamento, senza submit. */
  function setupAuthentication() {
    var node = document.querySelector('[data-webauthn="auth"]');
    if (!node || !window.PublicKeyCredential) {
      var missing = document.getElementById('wa-status');
      if (missing) missing.textContent = 'Questo browser non supporta le passkey.';
      return;
    }
    var status = document.getElementById('wa-status');
    var input = document.querySelector('input[name="webauthnResponse"]');
    var form = document.getElementById('mfa-form');

    jsonFetch(node.getAttribute('data-webauthn-options'), { credentials: 'same-origin' })
      .then(function (res) {
        if (!res.ok) throw new Error('options non disponibili');
        return res.json();
      })
      .then(function (options) {
        options.challenge = base64urlToBuffer(options.challenge);
        if (options.allowCredentials) {
          options.allowCredentials = options.allowCredentials.map(function (c) {
            return Object.assign({}, c, { id: base64urlToBuffer(c.id) });
          });
        }
        return navigator.credentials.get({ publicKey: options });
      })
      .then(function (assertion) {
        if (!input || !form) return;
        input.value = JSON.stringify({
          id: assertion.id,
          rawId: bufferToBase64url(assertion.rawId),
          type: assertion.type,
          response: {
            clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
            authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
            signature: bufferToBase64url(assertion.response.signature),
            userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null,
          },
        });
        form.submit();
      })
      .catch(function (err) {
        if (status) {
          status.textContent =
            err.name === 'NotAllowedError'
              ? 'Annullato. Puoi usare un codice TOTP o un codice di recupero.'
              : 'Operazione fallita: ' + err.message;
        }
      });
  }

  function bufferToBase64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /* --------------------------------------------------- conferma distruttiva */
  /* Il pulsante "Elimina account" chiede conferma senza JS inline. */
  function setupConfirmations() {
    var forms = document.querySelectorAll('form[data-confirm]');
    for (var i = 0; i < forms.length; i++) {
      forms[i].addEventListener('submit', function (event) {
        if (!window.confirm(forms[i].getAttribute('data-confirm'))) event.preventDefault();
      });
    }
  }

  function boot() {
    setupRegistration();
    setupAuthentication();
    setupConfirmations();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();