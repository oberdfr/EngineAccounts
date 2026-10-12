// Isolated Playwright tool harness. No application server, database or real account.
// Run using browser_run_code_unsafe({ filename: <absolute path to this file> }).
async (page) => {
  const context = await page.context().browser().newContext();
  const p = await context.newPage();
  try {
    const cdp = await context.newCDPSession(p);
    await cdp.send('WebAuthn.enable');
    const auth = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    } });
    const options = {
      challenge: 'c3ludGhldGljLXJlZ2lzdGVyLWNoYWxsZW5nZS0xMjM0NTY',
      rp: { id: 'accounts.example.test', name: 'Synthetic audit' },
      user: { id: 'c3ludGhldGljLXVzZXI', name: 'synthetic@example.test', displayName: 'Synthetic' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' }, attestation: 'none',
    };
    await p.route('https://accounts.example.test/**', r => r.fulfill({ contentType: 'text/html', body: '<!doctype html><title>Synthetic audit</title><div id="fixture"></div>' }));
    await p.goto('https://accounts.example.test/');
    await p.evaluate(options => {
      document.getElementById('fixture').innerHTML = '<form id="registration"><button data-webauthn="register">Register</button><input name="webauthnResponse"><p id="wa-status"></p><script id="wa-options" type="application/json">' + JSON.stringify(options) + '</scr' + 'ipt></form>';
      document.getElementById('registration').submit = function () { window.__registration = JSON.parse(this.querySelector('input').value); };
      const realCreate = navigator.credentials.create.bind(navigator.credentials);
      let cancelled = false;
      navigator.credentials.create = function (options) {
        if (!cancelled) { cancelled = true; return Promise.reject(new DOMException('Synthetic cancellation', 'NotAllowedError')); }
        return realCreate(options);
      };
    }, options);
    // This path is the shared workspace mount, not a copy of the client script.
    const clientPath = '/run/user/1000/gvfs/sftp:host=192.168.1.13/root/EngineAccounts/src/ui/static/app.js';
    await p.addScriptTag({ path: clientPath });
    await p.click('[data-webauthn="register"]');
    await p.waitForFunction(() => document.getElementById('wa-status').textContent.includes('NotAllowedError'));
    await p.click('[data-webauthn="register"]');
    await p.waitForFunction(() => !!window.__registration);
    const registration = await p.evaluate(() => window.__registration);
    if (!registration.response.transports.includes('internal')) throw new Error('Missing response transports');
    const credentials = await cdp.send('WebAuthn.getCredentials', { authenticatorId: auth.authenticatorId });
    if (credentials.credentials.length !== 1) throw new Error('Registration failed');
    const authOptions = { challenge: 'c3ludGhldGljLWF1dGgtY2hhbGxlbmdlLTEyMzQ1Ng', rpId: 'accounts.example.test', userVerification: 'required' };
    await p.route('https://accounts.example.test/options', r => r.fulfill({ contentType: 'application/json', body: JSON.stringify(authOptions) }));
    await p.evaluate(() => {
      document.getElementById('fixture').innerHTML = '<form id="mfa-form"><div data-webauthn="auth" data-webauthn-options="/options"><p id="wa-status"></p></div><input name="webauthnResponse"><button>Authenticate</button></form>';
      document.getElementById('mfa-form').submit = function () { window.__assertion = JSON.parse(this.querySelector('input').value); };
    });
    await p.addScriptTag({ path: clientPath });
    await p.waitForFunction(() => !!window.__assertion);
    const assertion = await p.evaluate(() => window.__assertion);
    if (assertion.id !== registration.id || assertion.response.userHandle !== options.user.id) throw new Error('Account binding mismatch');
    return JSON.stringify({ registration, assertion, registrationRetry: true, virtualCredentialCount: 1 });
  } finally { await context.close(); }
}
