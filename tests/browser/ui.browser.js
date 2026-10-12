/* Run ONLY after all UI edits settle, with playwright.browser_run_code_unsafe.
 * Start: npx tsx tests/browser/ui-fixture.ts; forward engine loopback 18081.
 * Synthetic data only. Screenshots are workspace .playwright-mcp paths.
 */
async (page) => {
  const context = await page.context().browser().newContext({ javaScriptEnabled: false, reducedMotion: 'reduce' });
  const testPage = await context.newPage();
  const results = [];
  const failures = [];
  const screenshots = [];
  const paths = ['account', 'profile', 'security', 'sessions', 'apps', 'services', 'activity', 'export', 'delete', 'totp', 'passkey', 'recovery', 'login', 'admin', 'admin/reauth', 'admin/accounts', 'admin/accounts/00000000-0000-4000-8000-000000000001', 'admin/services', 'admin/services/assigned', 'admin/settings', 'admin/audit', 'admin/diagnostics', 'fixture/service-admin/', 'fixture/service-admin/reauth', 'fixture/service-admin/accounts', 'fixture/service-admin/accounts/00000000-0000-4000-8000-000000000001', 'fixture/admin-mfa', 'fixture/admin-password-only'];
  const capture = async (target, name) => {
    const path = `.playwright-mcp/engineaccounts-redesign-${name}.png`;
    await target.evaluate(() => { document.activeElement?.blur(); window.scrollTo(0, 0); });
    await target.screenshot({ path, fullPage: true, animations: 'disabled' });
    screenshots.push(path);
  };
  const fontRequests = [];
  testPage.on('response', response => {
    if (response.url().includes('/static/fonts/')) fontRequests.push({ url: response.url(), status: response.status() });
  });
  try {
    for (const width of [320, 390, 768, 1440, 1920]) {
      await testPage.setViewportSize({ width, height: 1000 });
      for (const path of paths) {
        const response = await testPage.goto(`http://127.0.0.1:18081/${path}`);
        if (!response || ![200, 403].includes(response.status())) failures.push(`${width}/${path}: HTTP ${response?.status()}`);
        await testPage.evaluate(() => document.fonts.ready);
        const check = await testPage.evaluate(() => {
          const visible = e => {
            if (!e.getClientRects().length || getComputedStyle(e).visibility === 'hidden') return false;
            for (let parent = e.parentElement; parent; parent = parent.parentElement) {
              if (parent.matches('details:not([open])') && !parent.querySelector(':scope > summary')?.contains(e)) return false;
            }
            return true;
          };
          const controls = [...document.querySelectorAll('button,.button,nav a,summary,input:not([type=hidden]),select')].filter(visible);
          const seconds = value => value.split(',').map(parseFloat);
          const motion = [...document.querySelectorAll('*')].filter(visible).filter(e => {
            const style = getComputedStyle(e);
            return (style.animationName !== 'none' && seconds(style.animationDuration).some(s => s > 0.01)) || seconds(style.transitionDuration).some(s => s > 0.01);
          }).map(e => e.tagName + '.' + e.className);
          return { h1: document.querySelectorAll('h1').length, overflow: document.documentElement.scrollWidth > innerWidth, small: controls.filter(e => e.getBoundingClientRect().height < 43.9 || e.getBoundingClientRect().width < 43.9).map(e => e.outerHTML), fonts: [...document.fonts].filter(f => f.status === 'loaded').map(f => f.family), regions: [...document.querySelectorAll('.table-scroll')].every(e => e.getAttribute('aria-label') && e.getAttribute('tabindex') === '0'), motion };
        });
        if (check.h1 !== 1 || check.overflow || check.small.length || !check.regions || check.motion.length || !check.fonts.includes('Geist Variable') || !check.fonts.includes('Inter Variable')) failures.push(`${width}/${path}: ${JSON.stringify(check)}`);
        if (await testPage.locator('.mobile-nav > summary').isVisible() && path !== 'login') {
          await testPage.locator('.mobile-nav > summary').click();
          if (!await testPage.locator('.mobile-nav a[href="/account/security"]').isVisible()) failures.push(`${width}/${path}: native menu did not open without JavaScript`);
          await testPage.locator('.mobile-nav > summary').click();
        }
        if (path === 'admin/accounts/00000000-0000-4000-8000-000000000001') {
          const action = testPage.locator('details').filter({ has: testPage.locator('input[name="action"][value="ban"]') });
          await action.locator('summary').click();
          if (!await action.getByLabel('Scrivi CONFERMA per procedere').isVisible()) failures.push(`${width}/${path}: native action disclosure did not open`);
          await action.locator('summary').click();
        }
        if (path === 'passkey' && !await testPage.locator('noscript').isVisible()) failures.push(`${width}/${path}: missing no-JS passkey explanation`);
        if (path.startsWith('fixture/service-admin/') && !await testPage.getByText('Ambito limitato a questo servizio:', { exact: false }).isVisible()) failures.push(`${width}/${path}: service scope missing`);
        await testPage.keyboard.press('Control+Home');
        await testPage.evaluate(() => { document.body.setAttribute('tabindex', '-1'); document.body.focus({ preventScroll: true }); document.body.removeAttribute('tabindex'); window.scrollTo(0, 0); });
        await testPage.keyboard.press('Tab');
        const focus = await testPage.evaluate(() => {
          const element = document.activeElement;
          const style = getComputedStyle(element);
          const rect = element.getBoundingClientRect();
          return { visible: rect.width > 0 && rect.height > 0 && rect.top >= 0 && rect.bottom <= innerHeight, outline: style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) >= 2 };
        });
        if (!focus.visible || !focus.outline) failures.push(`${width}/${path}: keyboard focus ${JSON.stringify(focus)}`);
        if ([390, 1440].includes(width) || (['account', 'profile', 'security', 'sessions', 'totp', 'passkey', 'login', 'admin', 'fixture/service-admin/'].includes(path) && [320, 1920].includes(width))) {
          await capture(testPage, `${path.replaceAll('/', '-')}-${width}-nojs`);
        }
        results.push({ width, path, ...check, focus });
      }
    }
    // The same responsive matrix with enhancement enabled; native no-JS coverage stays separate.
    const enhanced = await page.context().browser().newContext({ javaScriptEnabled: true, reducedMotion: 'reduce' });
    const enhancedResults = [];
    try {
      const enhancedPage = await enhanced.newPage();
      const errors = [];
      enhancedPage.on('pageerror', error => errors.push(error.message));
      // Never invoke an actual platform authenticator during visual tests.
      await enhanced.addInitScript(() => {
        if (navigator.credentials) Object.defineProperty(navigator.credentials, 'create', { value: async () => { throw new DOMException('Synthetic fixture: authenticator deliberately not invoked', 'NotAllowedError'); } });
      });
      for (const width of [320, 390, 768, 1440, 1920]) {
        await enhancedPage.setViewportSize({ width, height: 1000 });
        for (const path of paths) {
          await enhancedPage.goto(`http://127.0.0.1:18081/${path}`);
          await enhancedPage.evaluate(() => document.fonts.ready);
          const overflow = await enhancedPage.evaluate(() => document.documentElement.scrollWidth > innerWidth);
          if (overflow) failures.push(`${width}/${path}/JS: overflow`);
          enhancedResults.push({ width, path, overflow });
          if (width === 390 && ['account', 'totp', 'passkey', 'admin'].includes(path)) await capture(enhancedPage, `${path}-${width}-js`);
        }
      }
      await enhancedPage.goto('http://127.0.0.1:18081/account');
      const preference = enhancedPage.locator('[data-animation-preference]');
      if (await preference.isChecked()) failures.push('Animation preference must default to off');
      await preference.check();
      await enhancedPage.reload();
      if (!await preference.isChecked() || !await enhancedPage.evaluate(() => document.documentElement.dataset.animations === 'true')) failures.push('Animation preference did not persist');
      const motionDespiteReduction = await enhancedPage.evaluate(() => [...document.querySelectorAll('*')].some(e => {
        const style = getComputedStyle(e);
        return (style.animationName !== 'none' && style.animationDuration.split(',').some(s => parseFloat(s) > 0.01)) || style.transitionDuration.split(',').some(s => parseFloat(s) > 0.01);
      }));
      if (motionDespiteReduction) failures.push('Reduced-motion preference must override enabled animations');
      await preference.uncheck();
      if (errors.length) failures.push(`JavaScript errors: ${JSON.stringify(errors)}`);
    } finally { await enhanced.close(); }
    // Browser-zoom-equivalent layout reflow: half the CSS viewport at 2x pixel density.
    // This does not claim interaction with the browser's native zoom setting.
    const zoomContext = await page.context().browser().newContext({ javaScriptEnabled: false, reducedMotion: 'reduce', deviceScaleFactor: 2 });
    const zoomResults = [];
    try {
      const zoomPage = await zoomContext.newPage();
      for (const physicalWidth of [768, 1440, 1920]) {
        await zoomPage.setViewportSize({ width: physicalWidth / 2, height: 500 });
        for (const path of ['account', 'profile', 'security', 'sessions', 'totp', 'passkey', 'login', 'activity', 'services', 'admin']) {
          await zoomPage.goto(`http://127.0.0.1:18081/${path}`);
          await zoomPage.evaluate(() => document.fonts.ready);
          const overflow = await zoomPage.evaluate(() => document.documentElement.scrollWidth > innerWidth);
          if (overflow) failures.push(`200% equivalent reflow ${physicalWidth}/${path}: overflow`);
          zoomResults.push({ physicalWidth, cssWidth: physicalWidth / 2, path, overflow });
          if (physicalWidth === 1440 && path === 'account') await zoomPage.screenshot({ path: '.playwright-mcp/engineaccounts-ui-account-1440-200pct-reflow.png', fullPage: true });
        }
      }
    } finally { await zoomContext.close(); }
    if (!fontRequests.length || fontRequests.some(r => new URL(r.url).origin !== 'http://127.0.0.1:18081' || r.status !== 200)) throw new Error(`Fonts not served locally: ${JSON.stringify(fontRequests)}`);
    const dialogContext = await page.context().browser().newContext({ reducedMotion: 'reduce', viewport: { width: 390, height: 844 } });
    const dialogResults = [];
    try {
      const dialogPage = await dialogContext.newPage();
      let submissions = 0;
      dialogPage.on('request', request => { if (request.method() === 'POST' && new URL(request.url()).pathname === '/fixture/delete') submissions++; });
      await dialogPage.goto('http://127.0.0.1:18081/fixture/delete');
      await dialogPage.getByLabel('Password attuale').fill('synthetic-password');
      await dialogPage.getByLabel('Scrivi ELIMINA per confermare').fill('ELIMINA');
      const trigger = dialogPage.getByRole('button', { name: 'Elimina definitivamente', exact: true });
      for (const dismiss of ['cancel', 'escape', 'confirm']) {
        await trigger.click();
        const dialog = dialogPage.getByRole('dialog', { name: 'Conferma operazione' });
        await dialog.waitFor({ state: 'visible' });
        if (!await dialogPage.evaluate(() => document.querySelector('dialog').matches(':modal') && document.activeElement.textContent === 'Annulla')) throw new Error('Dialog not native modal / initial cancel focus');
        for (const key of ['Tab', 'Tab', 'Shift+Tab', 'Shift+Tab']) {
          await dialogPage.keyboard.press(key);
          // Chromium can move Tab to browser chrome (document.hasFocus() false),
          // but must never focus an interactive element behind the modal.
          if (!await dialogPage.evaluate(() => !document.hasFocus() || document.querySelector('dialog').contains(document.activeElement))) throw new Error('Focus escaped native dialog into background');
        }
        if (!await dialogPage.evaluate(() => { document.querySelector('.brand').focus(); return document.querySelector('dialog').contains(document.activeElement); })) throw new Error('Modal background is not inert');
        const overflow = await dialogPage.evaluate(() => document.documentElement.scrollWidth > innerWidth);
        if (overflow) throw new Error('Dialog overflow at 390px');
        if (dismiss === 'cancel') {
          await dialogPage.screenshot({ path: '.playwright-mcp/engineaccounts-ui-delete-dialog-390.png', fullPage: true });
          await dialog.getByRole('button', { name: 'Annulla', exact: true }).click();
        } else if (dismiss === 'escape') {
          await dialogPage.keyboard.press('Escape');
        } else {
          await dialog.getByRole('button', { name: 'Conferma', exact: true }).click();
          await dialogPage.getByRole('heading', { name: 'Invio sintetico ricevuto' }).waitFor();
        }
        if (dismiss !== 'confirm') {
          await dialog.waitFor({ state: 'detached' });
          if (!await trigger.evaluate(element => document.activeElement === element)) throw new Error(`${dismiss}: focus not restored`);
          if (submissions !== 0) throw new Error(`${dismiss}: unexpected submission`);
        }
        dialogResults.push({ dismiss, focusConfined: true, overflow, submissions });
      }
      if (submissions !== 1) throw new Error(`Expected exactly one synthetic POST, got ${submissions}`);
    } finally { await dialogContext.close(); }
    return { passed: failures.length === 0, failures, checkedNoJS: results.length, checkedJS: enhancedResults.length, reducedMotion: true, screenshots, fontRequests, zoomMethod: '200% equivalent reflow, not native browser zoom', zoomResults, enhancedResults, dialogResults, dialogCoverage: 'Product accountDeletePage data-confirm and app.js; only POST action redirected to synthetic handler. Real authenticator deliberately not invoked.', results };
  } finally { await context.close(); }
}

/* Targeted follow-up ONLY after parent confirms pages + header edits are complete.
 * Pass accountPolishBrowserAudit to browser_run_code_unsafe, not the legacy
 * full-matrix arrow above. Fixture must be restarted to load current renderers.
 * Screenshots use the explicitly approved absolute paths below.
 */
async function accountPolishBrowserAudit(page, { selectsOnly = false } = {}) {
  const browser = page.context().browser();
  const failures = [], results = [], selectResults = [], screenshots = [], errors = [], assets = [], cspErrors = [];
  const expect = (ok, message) => { if (!ok) failures.push(message); };
  const url = (name, role) => `http://127.0.0.1:18081/fixture/account-polish/${name}?role=${role}`;
  const capture = async (p, name, openSelect = false) => {
    const path = `/tmp/opencode/engineaccounts-nav-selects-${name}.png`;
    if (!openSelect) await p.evaluate(() => { document.activeElement?.blur(); window.scrollTo(0, 0); });
    // Preserve focused combobox and viewport position for top-layer popovers.
    await p.screenshot({ path, fullPage: !openSelect, animations: 'disabled' });
    screenshots.push(path);
  };
  for (const javaScriptEnabled of [false, true]) {
    const context = await browser.newContext({ javaScriptEnabled, reducedMotion: 'reduce' });
    try {
      const p = await context.newPage();
      p.on('pageerror', error => errors.push(error.message));
      p.on('console', message => { if (message.type() === 'error' && /content security|content-security|violat|refused to/i.test(message.text())) cspErrors.push(message.text()); });
      p.on('response', response => {
        if (/\/static\/(?:header|select)-controls\.(css|js)/.test(response.url())) assets.push({ url: response.url(), status: response.status() });
      });
      for (const width of [320, 390, 768, 1440, 1920]) {
        await p.setViewportSize({ width, height: 1000 });
        for (const role of selectsOnly ? [] : ['global', 'ordinary', 'assigned']) {
          for (const name of ['home', 'profile', 'security', 'export']) {
            const label = `${javaScriptEnabled ? 'JS' : 'noJS'}/${width}/${role}/${name}`;
            const response = await p.goto(url(name, role));
            expect(response?.status() === 200, `${label}: HTTP ${response?.status()}`);
            await p.evaluate(() => document.fonts.ready);
            const check = await p.evaluate(() => {
              const visible = e => !!e.getClientRects().length && getComputedStyle(e).visibility !== 'hidden' && !e.closest('details:not([open]) :not(summary):not(summary *)');
              const rect = e => { const r = e.getBoundingClientRect(); return { x: r.x, y: r.y, width: r.width, height: r.height, right: r.right, bottom: r.bottom }; };
              const controls = [...document.querySelectorAll('.area-navigation a,.identity-menu > summary')].filter(visible);
              const title = document.querySelector('.identity-heading h2'), badge = document.querySelector('.identity-heading .badge');
              const totp = document.querySelector('#totp'), disclosure = document.querySelector('.totp-manage');
              return {
                h1: document.querySelectorAll('h1').length,
                overflow: document.documentElement.scrollWidth > innerWidth,
                header: controls.map(rect),
                sidebarAdmin: document.querySelectorAll('.account-sidebar a[href^="/admin"]').length,
                headings: [...document.querySelectorAll('main h2')].map(e => e.textContent.trim()),
                adjacent: title && badge ? { title: rect(title), badge: rect(badge), alignment: getComputedStyle(title.parentElement).alignItems } : null,
                totp: totp ? { height: rect(totp).height, bottomGap: rect(totp).bottom - rect(disclosure).bottom, align: getComputedStyle(totp.parentElement).alignItems, state: !!document.querySelector('.totp-state'), collapsed: !disclosure.open } : null,
                exportMargin: document.querySelector('.export-actions') ? getComputedStyle(document.querySelector('.export-actions')).marginTop : null,
                sessionsHints: [...document.querySelectorAll('.dashboard-grid .card')].find(e => e.querySelector('h2')?.textContent === 'Sessioni')?.querySelectorAll('.hint').length,
                motion: [...document.querySelectorAll('*')].some(e => { const s = getComputedStyle(e); return (s.animationName !== 'none' && s.animationDuration.split(',').some(v => parseFloat(v) > .01)) || s.transitionDuration.split(',').some(v => parseFloat(v) > .01); }),
              };
            });
            expect(check.h1 === 1 && !check.overflow && !check.motion, `${label}: layout/motion ${JSON.stringify(check)}`);
            expect(check.header.length === (role === 'ordinary' ? 2 : 3) && check.header.every(r => r.height >= 44 && r.width >= 44 && r.x >= 0 && r.right <= width && r.y >= 0 && r.bottom <= 160), `${label}: inaccessible header ${JSON.stringify(check.header)}`);
            expect(check.sidebarAdmin === 0, `${label}: Admin leaked into account sidebar`);
            if (name === 'profile') expect(!check.headings.some(h => /amministraz|servizi collegati|ruoli.*servizi/i.test(h)), `${label}: administrative/service profile panel`);
            if (name === 'home') {
              expect(check.sessionsHints === 0, `${label}: dashboard sessions hint retained`);
              if (width >= 1440) expect(check.adjacent && check.adjacent.badge.x >= check.adjacent.title.right && check.adjacent.badge.x - check.adjacent.title.right <= 20 && Math.abs((check.adjacent.badge.y + check.adjacent.badge.height / 2) - (check.adjacent.title.y + check.adjacent.title.height / 2)) <= 3, `${label}: email badge not adjacent on the same line`);
              if (role === 'global') expect(await p.getByText('Il tuo account è un amministratore.', { exact: true }).count() === 1, `${label}: admin card copy`);
            }
            if (name === 'export') expect(check.exportMargin === '32px', `${label}: export margin ${check.exportMargin}`);
            if (name === 'security') {
              expect(check.totp?.state && check.totp.collapsed && check.totp.align === 'start' && check.totp.bottomGap <= 30, `${label}: TOTP empty/stretch card ${JSON.stringify(check.totp)}`);
              await p.locator('.totp-manage > summary').click();
              const spacing = await p.locator('.totp-manage form').evaluate(form => {
                const field = form.querySelector('.field').getBoundingClientRect();
                const button = form.querySelector('button').getBoundingClientRect();
                return { gap: button.top - field.bottom, formClass: form.className, visible: button.width > 0 && button.height >= 44 };
              });
              expect(spacing.visible && spacing.gap >= 16 && spacing.formClass.includes('stack'), `${label}: disable form spacing ${JSON.stringify(spacing)}`);
              await p.locator('.totp-manage > summary').click();
            }
            const area = p.locator('.area-navigation');
            const links = area.locator('a');
            const expected = role === 'global' ? ['/account', '/admin'] : role === 'assigned' ? ['/account', '/admin/services/assigned'] : ['/account'];
            const actual = await links.evaluateAll(es => es.map(e => e.getAttribute('href')));
            expect(JSON.stringify(actual) === JSON.stringify(expected) && await links.first().isVisible(), `${label}: authorized area links ${JSON.stringify(actual)}`);
            expect(await links.first().getAttribute('aria-current') === 'page' && await area.locator('[aria-current="page"]').count() === 1, `${label}: selected Account pill`);
            expect(await area.locator('button,details,[aria-haspopup]').count() === 0, `${label}: area navigation must not be a dropdown`);
            const pill = await links.first().evaluate(e => { const s = getComputedStyle(e); return { radius: parseFloat(s.borderRadius), background: s.backgroundColor }; });
            expect(pill.radius >= 20 && pill.background !== 'rgba(0, 0, 0, 0)', `${label}: active pill material ${JSON.stringify(pill)}`);
            const identity = p.locator('[data-identity-menu]');
            const identityTrigger = identity.locator('summary');
            await identityTrigger.focus();
            await p.keyboard.press('Enter');
            expect(await identity.locator('a[href="/account/profile"]').isVisible(), `${label}: identity keyboard open`);
            expect(await identity.locator('form[action="/account/logout"][method="post"] input[name="_csrf"]').count() === 1, `${label}: native CSRF POST logout`);
            if (javaScriptEnabled) {
              await p.keyboard.press('Escape');
              expect(!await identity.evaluate(e => e.open) && await identityTrigger.evaluate(e => document.activeElement === e), `${label}: identity Escape`);
              await identityTrigger.click();
              await p.mouse.click(8, 500);
              expect(!await identity.evaluate(e => e.open), `${label}: identity outside click`);
              await identityTrigger.focus();
              await p.keyboard.press('Enter');
              await p.keyboard.press('Tab');
              expect(await identity.locator('a[href="/account/profile"]').evaluate(e => document.activeElement === e), `${label}: identity Tab to profile`);
              await identityTrigger.click();
            } else await identityTrigger.click();
            if (javaScriptEnabled && role === 'global') {
              if (name === 'home' && width === 1440) await capture(p, 'header1440');
            }
            results.push({ label, ...check });
          }
          // Verify keyboard activation navigates, not merely highlights an option.
          await p.goto(url('home', role));
          const area = p.locator('.area-navigation');
          const destination = area.locator('a').last();
          const href = await destination.getAttribute('href');
          await destination.focus();
          await Promise.all([p.waitForURL(u => u.pathname === href), p.keyboard.press('Enter')]);
          expect(new URL(p.url()).pathname === href, `${width}/${role}/${javaScriptEnabled}: keyboard destination`);
          expect((await p.locator('.area-navigation a[aria-current="page"]').textContent()).trim() === (href === '/account' ? 'Account' : 'Admin'), `${width}/${role}/${javaScriptEnabled}: destination selected pill`);
        }
        const selectLabel = `${javaScriptEnabled ? 'JS' : 'noJS'}/${width}`;
        const control = id => javaScriptEnabled ? p.locator(`select[id="${id}"]`).locator('..').locator('.ea-select-trigger') : p.locator(`select[id="${id}"]`);
        const choose = async (id, value) => {
          const native = p.locator(`select[id="${id}"]`);
          if (!javaScriptEnabled) await native.selectOption(value);
          else {
            const label = await native.locator(`option[value="${value}"]`).textContent();
            await control(id).click();
            const menu = p.locator(`#${await control(id).getAttribute('aria-controls')}`);
            await menu.getByRole('option', { name: label, exact: true }).click();
          }
          expect(await native.inputValue() === value, `${selectLabel}/${id}: native value synchronization`);
        };
        const inspectSelect = async (id, label) => {
          const c = control(id);
          expect(await p.getByRole('combobox', { name: label, exact: true }).count() === 1, `${selectLabel}/${id}: accessible label`);
          const appearance = await c.evaluate(e => { const s = getComputedStyle(e); const r = e.getBoundingClientRect(); const a = e.querySelector('svg'); return { paddingRight: s.paddingRight, arrowRight: a ? getComputedStyle(a).right : s.backgroundPosition, height: r.height, right: r.right, left: r.left }; });
          expect(appearance.paddingRight === '48px' && (javaScriptEnabled ? appearance.arrowRight === '16px' : appearance.arrowRight.includes('16px')) && appearance.height >= 44 && appearance.left >= 0 && appearance.right <= width, `${selectLabel}/${id}: select appearance ${JSON.stringify(appearance)}`);
          if (javaScriptEnabled) expect(await p.locator(`select[id="${id}"]`).getAttribute('aria-hidden') === 'true', `${selectLabel}/${id}: duplicate accessible native select`);
          if (javaScriptEnabled) expect(await c.evaluate(e => !!document.getElementById(e.getAttribute('aria-controls'))), `${selectLabel}/${id}: initial aria-controls target exists`);
          return appearance;
        };
        const menuBounds = async (id, edge) => {
          await control(id).click();
          const menu = p.locator(`#${await control(id).getAttribute('aria-controls')}`);
          const bounds = await menu.evaluate(e => { const r = e.getBoundingClientRect(), s = getComputedStyle(e); return { x: r.x, y: r.y, right: r.right, bottom: r.bottom, height: r.height, position: s.position, radius: s.borderRadius, background: s.backgroundColor, blur: s.backdropFilter, scrollHeight: e.scrollHeight, clientHeight: e.clientHeight, topLayer: e.matches(':popover-open') }; });
          expect(bounds.x >= 0 && bounds.right <= width + 1 && bounds.y >= 0 && bounds.bottom <= 1001 && bounds.height > 0 && bounds.position === 'fixed' && bounds.radius === '16px', `${selectLabel}/${id}/${edge}: clipped popover ${JSON.stringify(bounds)}`);
          await p.keyboard.press('Escape');
          return bounds;
        };
        // Actual admin renderer, actual query filter parsing; only store is synthetic.
        await p.goto('http://127.0.0.1:18081/admin/accounts');
        await p.evaluate(() => document.fonts.ready);
        expect(!await p.evaluate(() => document.documentElement.scrollWidth > innerWidth), `${selectLabel}: admin filter page overflow`);
        const filters = [];
        for (const [id, name] of [['filter-status', 'Stato account'], ['filter-mfa', 'Autenticazione a più fattori (MFA)'], ['filter-role', 'Ruolo amministrativo']]) filters.push(await inspectSelect(id, name));
        expect(await p.locator('.area-navigation a[aria-current="page"]').textContent() === 'Admin', `${selectLabel}: Admin active pill`);
        await p.getByLabel('Email, nome o identificatore account', { exact: true }).fill('synthetic-search');
        await choose('filter-status', 'blocked'); await choose('filter-mfa', 'enabled'); await choose('filter-role', 'service');
        await Promise.all([p.waitForURL(u => u.searchParams.get('status') === 'blocked'), p.getByRole('button', { name: 'Filtra account', exact: true }).click()]);
        const query = Object.fromEntries(new URL(p.url()).searchParams);
        expect(query.q === 'synthetic-search' && query.status === 'blocked' && query.mfa === 'enabled' && query.role === 'service', `${selectLabel}: actual admin GET ${JSON.stringify(query)}`);
        const parsedFilters = await p.evaluate(async () => (await (await fetch('/fixture/last-account-filters')).json()).filters);
        expect(parsedFilters.q === query.q && parsedFilters.status === query.status && parsedFilters.mfa === query.mfa && parsedFilters.role === query.role, `${selectLabel}: server filter parsing ${JSON.stringify(parsedFilters)}`);
        expect(await p.locator('#filter-status').inputValue() === 'blocked', `${selectLabel}: selected value survives GET`);
        await p.getByRole('link', { name: 'Azzera filtri', exact: true }).click();
        expect(await p.locator('#filter-status').inputValue() === '' && !new URL(p.url()).search, `${selectLabel}: real admin reset link`);
        if (javaScriptEnabled) {
          await control('filter-status').click();
          await p.keyboard.press('b'); await p.keyboard.press('Enter');
          expect(await p.locator('#filter-status').inputValue() === 'blocked', `${selectLabel}: filter typeahead Enter`);
          const menu = await menuBounds('filter-status', 'admin');
          if ([390, 1440].includes(width)) {
            await p.evaluate(() => window.scrollTo(0, 0));
            await control('filter-status').click();
            expect(await control('filter-status').getAttribute('aria-expanded') === 'true', `${selectLabel}: screenshot popover open`);
            await capture(p, width === 1440 ? 'admin1440' : 'admin390', true);
            await p.keyboard.press('Escape');
          }
          selectResults.push({ label: `${selectLabel}/admin/accounts`, filters, query, parsedFilters, menu });
        } else selectResults.push({ label: `${selectLabel}/admin/accounts`, filters, query, parsedFilters });
        // Real editable settings disclosures, with boolean and registration-mode selects.
        await p.goto('http://127.0.0.1:18081/admin/settings');
        expect(!await p.evaluate(() => document.documentElement.scrollWidth > innerWidth), `${selectLabel}: settings page overflow`);
        for (const [id, label, value] of [['setting-EMAIL_VERIFICATION_REQUIRED', 'Verifica email obbligatoria', 'false'], ['setting-registration', 'Registrazione account', 'invite']]) {
          await p.locator('details').filter({ has: p.locator(`select[id="${id}"]`) }).locator(':scope > summary').click();
          await inspectSelect(id, label); await choose(id, value);
          const submitted = await p.locator(`select[id="${id}"]`).evaluate(e => Object.fromEntries(new FormData(e.form)));
          expect(submitted.value === value && submitted.key === (id === 'setting-registration' ? 'REGISTRATION_MODE' : 'EMAIL_VERIFICATION_REQUIRED'), `${selectLabel}/${id}: native settings form data`);
          if (javaScriptEnabled) await menuBounds(id, 'settings');
        }
        selectResults.push({ label: `${selectLabel}/admin/settings`, booleanAndRegistration: true });
        // Required validation, optgroups, disabled fields and reset use safe GET only.
        await p.goto('http://127.0.0.1:18081/fixture/selects');
        expect(!await p.evaluate(() => document.documentElement.scrollWidth > innerWidth), `${selectLabel}: select fixture overflow`);
        await inspectSelect('select-top', 'Scelta principale');
        await inspectSelect('select-required', 'Scelta obbligatoria');
        expect(await control('select-disabled').isDisabled() && await control('select-fieldset').isDisabled(), `${selectLabel}: disabled select/fieldset`);
        await p.evaluate(() => { window.__selectEvents = []; const e = document.querySelector('#select-top'); for (const name of ['input', 'change']) e.addEventListener(name, () => window.__selectEvents.push(name)); });
        const top = control('select-top');
        if (javaScriptEnabled) {
          await p.locator('label[for="select-top"]').click();
          expect(await top.evaluate(e => document.activeElement === e), `${selectLabel}: label focus forwarding`);
          if (await top.getAttribute('aria-expanded') !== 'true') await top.click();
          const menu = p.locator(`#${await top.getAttribute('aria-controls')}`);
          expect(await menu.getByRole('group', { name: 'Disponibili' }).count() === 1 && await menu.getByRole('option', { name: 'Bloccata', exact: true }).getAttribute('aria-disabled') === 'true' && await menu.getByRole('option', { name: 'Non disponibile nel gruppo', exact: true }).getAttribute('aria-disabled') === 'true' && await menu.getByRole('option', { name: 'Nascosta', exact: true }).count() === 0, `${selectLabel}: optgroup/disabled/hidden options`);
          // Force sends a real pointer click despite Playwright's aria-disabled
          // guard; the enhancement itself must refuse this option.
          await menu.getByRole('option', { name: 'Bloccata', exact: true }).click({ force: true });
          expect(await p.locator('#select-top').inputValue() === 'alpha', `${selectLabel}: disabled option selected`);
          await p.keyboard.press('Home'); await p.keyboard.press('ArrowDown'); await p.keyboard.press('Enter');
          expect(await p.locator('#select-top').inputValue() === 'beta', `${selectLabel}: keyboard skips disabled option`);
          await top.click(); await p.keyboard.press('Home'); await p.keyboard.press('g'); await p.keyboard.press('Enter');
          expect(await p.locator('#select-top').inputValue() === 'gamma', `${selectLabel}: typeahead Enter`);
          await top.click(); await p.keyboard.press('Home'); await p.keyboard.press('Escape');
          expect(await p.locator('#select-top').inputValue() === 'gamma' && await top.getAttribute('aria-expanded') === 'false' && await top.evaluate(e => document.activeElement === e), `${selectLabel}: Escape cancels tentative selection`);
          await top.click(); await p.mouse.click(8, 500);
          expect(await top.getAttribute('aria-expanded') === 'false', `${selectLabel}: select outside dismissal`);
          await top.click(); await p.keyboard.press('Tab');
          expect(await top.getAttribute('aria-expanded') === 'false' && !await top.evaluate(e => document.activeElement === e), `${selectLabel}: nontrapping Tab`);
        } else {
          await p.locator('label[for="select-top"]').click();
          expect(await top.evaluate(e => document.activeElement === e), `${selectLabel}: native label focus`);
          await p.keyboard.press('Escape');
          await top.focus(); await p.keyboard.press('Home'); await p.keyboard.press('b');
          expect(await p.locator('#select-top').inputValue() === 'beta', `${selectLabel}: native keyboard typeahead`);
          await p.keyboard.press('Alt+ArrowDown'); await p.keyboard.press('Escape');
          expect(await p.locator('#select-top').inputValue() === 'beta', `${selectLabel}: native Escape preserves selection`);
          await p.keyboard.press('Alt+ArrowDown'); await p.keyboard.press('Enter');
          expect(await p.locator('#select-top').inputValue() === 'beta', `${selectLabel}: native Enter confirmation`);
          await p.keyboard.press('Alt+ArrowDown'); await p.mouse.click(8, 500);
          expect(await p.locator('#select-top').inputValue() === 'beta', `${selectLabel}: native outside dismissal preserves selection`);
          await top.focus();
          await p.keyboard.press('Tab');
        }
        const events = await p.evaluate(() => window.__selectEvents);
        // Browser no-JS mode suppresses event callbacks even when attached by
        // Playwright evaluate; native state/GET behavior is verified separately.
        if (javaScriptEnabled) expect(events.includes('input') && events.includes('change'), `${selectLabel}: native input/change events ${JSON.stringify(events)}`);
        await p.getByRole('button', { name: 'Invia selezioni sintetiche', exact: true }).click();
        expect(new URL(p.url()).pathname === '/fixture/selects' && !await p.locator('#select-required').evaluate(e => e.validity.valid), `${selectLabel}: required blocks submission`);
        if (javaScriptEnabled) expect(await control('select-required').getAttribute('aria-invalid') === 'true' && await control('select-required').evaluate(e => document.activeElement === e), `${selectLabel}: invalid proxy announced/focused`);
        if (javaScriptEnabled) {
          await p.getByRole('button', { name: 'Ripristina selezioni', exact: true }).click();
          await p.waitForFunction(() => document.querySelector('#select-top').parentElement.querySelector('button').textContent === 'Alpha' && document.querySelector('#select-required').parentElement.querySelector('button').getAttribute('aria-invalid') !== 'true');
          expect(await p.locator('#select-required').inputValue() === '', `${selectLabel}: invalid reset restores empty required default without keeping error state`);
          await choose('select-top', 'gamma');
        }
        await choose('select-required', 'yes');
        await p.getByRole('button', { name: 'Ripristina selezioni', exact: true }).click();
        expect(await p.locator('#select-top').inputValue() === 'alpha' && await p.locator('#select-required').inputValue() === '', `${selectLabel}: native form reset`);
        if (javaScriptEnabled) await p.waitForFunction(() => document.querySelector('#select-top').parentElement.querySelector('button').textContent === 'Alpha');
        const resetState = { nativeChoice: await p.locator('#select-top').inputValue(), nativeRequired: await p.locator('#select-required').inputValue(), proxyChoice: javaScriptEnabled ? await top.textContent() : null, proxyInvalid: javaScriptEnabled ? await control('select-required').getAttribute('aria-invalid') : null };
        if (javaScriptEnabled) expect(resetState.proxyChoice === 'Alpha' && resetState.proxyInvalid !== 'true', `${selectLabel}: proxy reset synchronization ${JSON.stringify(resetState)}`);
        let canceledReset;
        if (javaScriptEnabled) {
          await choose('select-top', 'beta'); await choose('select-required', 'yes');
          await p.evaluate(() => document.querySelector('#select-fixture-form').addEventListener('reset', e => e.preventDefault(), { once: true }));
          await p.getByRole('button', { name: 'Ripristina selezioni', exact: true }).click();
          // Observe after the deferred reset-sync task, without a fixed sleep.
          await p.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
          canceledReset = { choice: await p.locator('#select-top').inputValue(), required: await p.locator('#select-required').inputValue(), proxy: await top.textContent() };
          expect(canceledReset.choice === 'beta' && canceledReset.required === 'yes' && canceledReset.proxy === 'Beta', `${selectLabel}: canceled reset preserves native/proxy state ${JSON.stringify(canceledReset)}`);
        }
        let bottomMenu;
        if (javaScriptEnabled) {
          await p.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
          await inspectSelect('select-bottom', 'Lista lunga in fondo');
          bottomMenu = await menuBounds('select-bottom', 'bottom');
          const bottom = control('select-bottom'); await bottom.click(); await p.keyboard.press('End');
          const menu = p.locator(`#${await bottom.getAttribute('aria-controls')}`);
          const scroll = await menu.evaluate(e => ({ top: e.scrollTop, height: e.scrollHeight, client: e.clientHeight }));
          expect(scroll.top > 0 && scroll.height > scroll.client, `${selectLabel}: long option scroll-to-end ${JSON.stringify(scroll)}`);
          await p.keyboard.press('Enter'); expect(await p.locator('#select-bottom').inputValue() === 'item-24', `${selectLabel}: last option selection`);
          await p.evaluate(() => window.scrollTo(0, 0));
          await menuBounds('select-top', 'top');
          await p.evaluate(() => {
            const first = document.createElement('div'); first.id = 'dynamic-parent-a';
            const second = document.createElement('div'); second.id = 'dynamic-parent-b';
            const select = document.createElement('select'); select.id = 'dynamic-select'; select.setAttribute('aria-label', 'Select dinamico');
            select.add(new Option('Dinamico Alpha', 'alpha')); select.add(new Option('Dinamico Beta', 'beta'));
            first.append(select); document.querySelector('main').append(first, second);
          });
          await p.waitForFunction(() => !!document.querySelector('#dynamic-parent-a .ea-select-trigger'));
          const oldMenuId = await p.locator('#dynamic-parent-a .ea-select-trigger').getAttribute('aria-controls');
          expect(await p.evaluate(id => !!document.getElementById(id), oldMenuId), `${selectLabel}: dynamic initial aria-controls`);
          await p.evaluate(() => { const s = document.querySelector('#dynamic-select'); s.value = 'beta'; s.dispatchEvent(new Event('change', { bubbles: true })); document.querySelector('#dynamic-parent-b').append(s); });
          await p.waitForFunction(() => !!document.querySelector('#dynamic-parent-b .ea-select-trigger') && !document.querySelector('#dynamic-parent-a .ea-select-wrap'));
          expect(await p.locator('#dynamic-select').inputValue() === 'beta' && await p.locator('#dynamic-parent-b .ea-select-trigger').textContent() === 'Dinamico Beta', `${selectLabel}: reparent preserves value and re-enhances in new parent`);
          const newMenuId = await p.locator('#dynamic-parent-b .ea-select-trigger').getAttribute('aria-controls');
          await p.evaluate(() => document.querySelector('#dynamic-select').remove());
          await p.waitForFunction(() => !document.querySelector('#dynamic-select') && !document.querySelector('#dynamic-parent-b .ea-select-wrap'));
          expect(await p.evaluate(ids => ids.every(id => !document.getElementById(id)), [oldMenuId, newMenuId]), `${selectLabel}: removal does not resurrect native select or orphan popovers`);
        }
        await choose('select-top', 'beta'); await choose('select-required', 'yes');
        await Promise.all([p.waitForURL(u => u.pathname === '/fixture/select-result'), p.getByRole('button', { name: 'Invia selezioni sintetiche', exact: true }).click()]);
        const submitted = Object.fromEntries(new URL(p.url()).searchParams);
        expect(submitted.choice === 'beta' && submitted.requiredChoice === 'yes' && !('disabledChoice' in submitted) && !('fieldsetChoice' in submitted), `${selectLabel}: safe GET form successful controls ${JSON.stringify(submitted)}`);
        selectResults.push({ label: `${selectLabel}/fixture/selects`, events, resetState, canceledReset, submitted, bottomMenu, dynamicRegressionsChecked: javaScriptEnabled });
      }
      if (javaScriptEnabled && !selectsOnly) {
        await p.goto(url('home', 'global'));
        const preference = p.locator('[data-animation-preference]');
        expect(!await preference.isChecked(), 'Animations default off');
        await preference.check();
        await p.reload();
        expect(await preference.isChecked(), 'Animation preference persists');
        expect(!await p.evaluate(() => [...document.querySelectorAll('*')].some(e => { const s = getComputedStyle(e); return (s.animationName !== 'none' && parseFloat(s.animationDuration) > .01) || parseFloat(s.transitionDuration) > .01; })), 'Reduced motion overrides opt-in');
      }
    } finally { await context.close(); }
  }
  expect(!errors.length, `Browser errors: ${JSON.stringify(errors)}`);
  expect(!cspErrors.length, `CSP errors: ${JSON.stringify(cspErrors)}`);
  expect(assets.length > 0 && assets.every(a => a.status === 200), `Header assets: ${JSON.stringify(assets)}`);
  return { passed: failures.length === 0, checked: results.length, checkedSelectPages: selectResults.length, selectsOnly, failures, screenshots, errors, cspErrors, assetStatuses: [...new Set(assets.map(a => a.status))], results, selectResults, coverage: `${selectsOnly ? 'Select-only follow-up: 30' : '120 Account cases plus 30'} actual admin/settings and synthetic select pages; five widths, JS + native no-JS; native GET submissions only; no production mutations, database, authenticators or deployments.` };
}
