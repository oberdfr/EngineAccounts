/* Da eseguire con playwright.browser_run_code_unsafe(filename), dopo aver
   avviato logout-fixture.ts. Non legge cookie/sessioni dell'app reale. */
async (page) => {
  const context = await page.context().browser().newContext();
  const testPage = await context.newPage();
  const blocked = [];
  testPage.on('console', (message) => {
    if (message.text().includes('Content Security Policy') || message.text().includes('Content-Security-Policy')) blocked.push(true);
  });
  const results = [];
  try {
    for (const mode of ['auto', 'manual']) {
      const response = await testPage.goto(`http://127.0.0.1:18080/start?mode=${mode}`);
      const csp = response.headers()['content-security-policy'];
      if (!csp.includes("form-action 'self' http://127.0.0.1:15173")) throw new Error('Origine RP mancante nella CSP');
      if (!csp.includes("script-src 'self'") || !csp.includes("frame-ancestors 'none'")) throw new Error('Direttive CSP perse');
      if (mode === 'manual') await testPage.getByRole('button', { name: 'Esci', exact: true }).click();
      await testPage.waitForURL('http://127.0.0.1:15173/signed-out?state=browser-logout-state');
      if (await testPage.getByRole('heading').innerText() !== 'Uscita completata') throw new Error('Callback RP non raggiunta');
      const result = await (await context.request.get('http://127.0.0.1:18080/test-result')).json();
      if (result.confirmCount !== 1 || result.sessionExists) throw new Error('Sessione non chiusa con un solo POST');
      results.push({ mode, returnedToRP: true, confirmCount: result.confirmCount, sessionDestroyed: !result.sessionExists });
    }
    const rejected = await testPage.goto('http://127.0.0.1:18080/start?mode=unsafe');
    if (rejected.status() !== 400) throw new Error('Redirect estraneo non rifiutato');
    if (rejected.headers()['content-security-policy'].includes('15174')) throw new Error('Origine estranea ammessa nella CSP');
    const untouched = await (await context.request.get('http://127.0.0.1:18080/test-result')).json();
    if (untouched.confirmCount !== 0 || !untouched.sessionExists) throw new Error('Sessione modificata dal redirect estraneo');
    if (blocked.length) throw new Error('Violazione CSP nel browser');
    return { results, unregisteredRedirectRejected: true, cspViolations: blocked.length };
  } finally {
    await context.close();
  }
}
