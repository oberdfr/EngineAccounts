import { describe, it, expect } from 'vitest';
import type { Config } from '../../src/config.js';
import { completeWebauthnRegistration, verifyWebauthnAuthentication, webauthnRegistrationOptions, webauthnAuthenticationOptions, renderTotpQrSvg, currentTotpCode, verifyTotpCode, startTotpEnrolment } from '../../src/services/mfa.js';
import type { AccountsStore } from '../../src/domain/ports.js';
import { encrypt } from '../../src/security/crypto.js';
const config = { issuer: 'https://accounts.example.test', baseUrl: 'https://accounts.example.test' } as Config;
const user = { id: 'synthetic-user', email: 'synthetic@example.test', displayName: null };
const credential = { credentialId: 'synthetic-credential', publicKey: Buffer.alloc(1), counter: 0, transports: ['internal'] };

describe('MFA WebAuthn security contract', () => {
  it('requires device verification and excludes existing credentials', async () => {
    const options = await webauthnRegistrationOptions(config, user, [credential]);
    expect(options.rp.id).toBe('accounts.example.test');
    expect(Buffer.from(options.user.id, 'base64url').toString()).toBe(user.id);
    expect(options.authenticatorSelection?.userVerification).toBe('required');
    expect(options.excludeCredentials?.[0]?.id).toBe(credential.credentialId);
    expect((await webauthnAuthenticationOptions(config, [credential])).userVerification).toBe('required');
  });
  it('rejects credential ID and account handle mismatch before crypto verification', async () => {
    expect((await verifyWebauthnAuthentication(config, { id: 'other' }, 'challenge', user, credential)).verified).toBe(false);
    expect((await verifyWebauthnAuthentication(config, { id: credential.credentialId, response: { userHandle: Buffer.from('other-user').toString('base64url') } }, 'challenge', user, credential)).verified).toBe(false);
  });
  it('rejects malformed browser responses safely', async () => {
    expect((await completeWebauthnRegistration(config, {}, 'challenge', user)).verified).toBe(false);
  });
});
describe('local TOTP enrollment', () => {
  it('reuses pending enrollment and refuses to replace a confirmed factor', async () => {
    const dataKey = Buffer.alloc(32, 7);
    let saved = false;
    const record = { secretCt: encrypt(dataKey, 'JBSWY3DPEHPK3PXP'), confirmedAt: null as Date | null };
    const store = { getTotp: async () => record, saveTotp: async () => { saved = true; } } as unknown as AccountsStore;
    expect((await startTotpEnrolment(store, { ...config, dataKey }, user)).secret).toBe('JBSWY3DPEHPK3PXP');
    expect(saved).toBe(false);
    record.confirmedAt = new Date();
    await expect(startTotpEnrolment(store, { ...config, dataKey }, user)).rejects.toThrow('already enrolled');
    expect(saved).toBe(false);
  });
  it('renders a real QR SVG without an external image or reflected URI', async () => {
    const uri = 'otpauth://totp/Engine%20Accounts:synthetic%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=Engine%20Accounts';
    const svg = await renderTotpQrSvg(uri);
    expect(svg).toContain('<svg'); expect(svg).toContain('<path');
    expect(svg).not.toContain('JBSWY3DPEHPK3PXP'); expect(svg).not.toContain('<script'); expect(svg).not.toContain('<image');
    await expect(renderTotpQrSvg('https://external.example/')).rejects.toThrow();
  });
  it('accepts an authenticator-compatible synthetic code and rejects malformed codes', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    expect(await verifyTotpCode(secret, await currentTotpCode(secret))).toBe(true);
    expect(await verifyTotpCode(secret, '12345')).toBe(false);
  });
});
