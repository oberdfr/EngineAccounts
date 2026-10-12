import { describe, expect, it } from 'vitest';
import { accountHomePage, accountProfilePage, accountSecurityPage, accountExportPage, webauthnRegisterPage } from '../../src/ui/pages.js';

describe('account screens expose real information safely', () => {
  it('does not present login session counts as a count of physical devices', () => {
    const page = accountHomePage({ csrf: 'test', email: 'synthetic@example.test', displayName: 'Test',
      emailVerified: true, createdAt: new Date(), sessions: 28, consents: 0, hasTotp: false, passkeys: 0, recoveryLeft: 0 });
    expect(page).toContain('Sessioni di accesso attive');
    expect(page).not.toContain('Non sono dispositivi');
    expect(page).not.toContain('Dispositivi attivi');
  });
  it('exposes nonsecret account fields and encodes user-provided values', () => {
    const page = accountProfilePage({ csrf: 'test', email: 'synthetic@example.test', displayName: '<script>bad()</script>', emailVerified: true,
      account: { id: 'synthetic-id', status: 'active', createdAt: new Date(), updatedAt: new Date(), lastLoginAt: null,
        emailVerifiedAt: new Date(), isGlobalAdmin: true, mustChangePassword: false, failedLogins: 2 } });
    for (const label of ['Identificatore account', 'Ultima modifica', 'Ultimo accesso', 'Amministratore globale', 'Tentativi di accesso falliti']) expect(page).toContain(label);
    expect(page).not.toContain('<script>bad()');
    expect(page).toContain('&lt;script&gt;');
  });
  it('delivers real registration options to the WebAuthn script without script injection', () => {
    const optionsJson = JSON.stringify({ challenge: 'abc', user: { name: '</script><script>bad()</script>' } });
    const page = webauthnRegisterPage({ csrf: 'test', email: 'synthetic@example.test', optionsJson });
    const embedded = /<script type="application\/json" id="wa-options">([^]*?)<\/script>/.exec(page)?.[1];
    expect(embedded).toBeTruthy();
    expect(JSON.parse(embedded!)).toEqual(JSON.parse(optionsJson));
    expect(embedded).not.toContain('</script>');
    expect(page).toContain('<noscript>');
  });
  it('keeps the verification chip beside the name and uses the requested administrator copy', () => {
    const page = accountHomePage({ csrf: 'test', email: 'synthetic@example.test', displayName: 'Persona',
      emailVerified: false, createdAt: new Date(), sessions: 2, consents: 0, hasTotp: false, passkeys: 0, recoveryLeft: 0, isGlobalAdmin: true });
    expect(page).toContain('class="identity-heading"><h2>Persona</h2><span class="badge warning">');
    expect(page).toContain('Il tuo account è un amministratore.');
    expect(page).toContain('Gestisci account, ruoli, servizi e attività della suite.');
    expect(page).not.toContain('È richiesto un secondo fattore e le azioni sensibili');
  });
  it('keeps service administration out of the profile content', () => {
    const page = accountProfilePage({ csrf: 'test', email: 'synthetic@example.test', displayName: 'Persona', emailVerified: true,
      serviceRoles: [{ serviceId: 'demo', name: 'Demo', admin: true }] });
    expect(page).not.toContain('<h3>Amministrazione servizi</h3>');
    expect(page).not.toContain('Gestisci servizio');
  });
  it('places TOTP removal in an explicit disclosure with a spaced form', () => {
    const page = accountSecurityPage({ csrf: 'test', email: 'synthetic@example.test', hasTotp: true, totpConfirmed: true, passkeys: [], recoveryLeft: 0 });
    expect(page).toContain('<details class="totp-manage">');
    expect(page).toContain('<form class="stack" method="post" action="/account/security/totp/disable">');
    expect(page).toContain('Disattiva TOTP');
    expect(page).not.toContain('Stato: <strong>attivo</strong>');
  });
  it('gives the export download a dedicated action group', () => {
    const page = accountExportPage({ csrf: 'test', email: 'synthetic@example.test', downloadUrl: '/account/export/download' });
    expect(page).toContain('<div class="export-actions">');
    expect(page).toContain('download="engine-accounts-export.json"');
  });
});
