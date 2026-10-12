import { describe, it, expect } from 'vitest';
import type { Config } from '../../src/config.js';
import { completeWebauthnRegistration, verifyWebauthnAuthentication } from '../../src/services/mfa.js';

// Public responses captured from tests/browser/mfa-audit.playwright.js on an isolated
// Chromium virtual authenticator. Synthetic account; no private key or real secrets.
const config = { issuer: 'https://accounts.example.test', baseUrl: 'https://accounts.example.test' } as Config;
const user = { id: 'synthetic-user' };
const registration = {
  id: 'vh-ANllhhTI6M4Rtg4qQJQY_RXqgl25W78nHqP82ScQ', rawId: 'vh-ANllhhTI6M4Rtg4qQJQY_RXqgl25W78nHqP82ScQ', type: 'public-key',
  response: {
    clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiYzNsdWRHaGxkR2xqTFhKbFoybHpkR1Z5TFdOb1lXeHNaVzVuWlMweE1qTTBOVFkiLCJvcmlnaW4iOiJodHRwczovL2FjY291bnRzLmV4YW1wbGUudGVzdCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9',
    attestationObject: 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViky0-U1QjRQzzbmd5IIqv2IEF6eWdoWmO9Z2XCx5ISU0hFAAAAAQECAwQFBgcIAQIDBAUGBwgAIL4fgDZZYYUyOjOEbYOKkCUGP0V6oJduVu_Jx6j_NknEpQECAyYgASFYIGDtVi-9YWSVU_kBEfYJZhyKOOAxAGXdbytpw46zYvAHIlggkHK55g_1isfBzpXaa_6lAYI14NKzcIzd3k1tH19_n0w',
    transports: ['internal'],
  }, clientExtensionResults: {},
};
const assertion = {
  id: registration.id, rawId: registration.id, type: 'public-key', clientExtensionResults: {},
  response: {
    clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYzNsdWRHaGxkR2xqTFdGMWRHZ3RZMmhoYkd4bGJtZGxMVEV5TXpRMU5nIiwib3JpZ2luIjoiaHR0cHM6Ly9hY2NvdW50cy5leGFtcGxlLnRlc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
    authenticatorData: 'y0-U1QjRQzzbmd5IIqv2IEF6eWdoWmO9Z2XCx5ISU0gFAAAAAg',
    signature: 'MEUCIQDqpHOEygm9mrdDDHXCFXXw8wNn1ObPp6hNgHwtK93x9QIgYcLj55QcdE9p-E-ZZFcab6yeBLa5txYfTS4BtXINzKg',
    userHandle: 'c3ludGhldGljLXVzZXI',
  },
};
const registerChallenge = 'c3ludGhldGljLXJlZ2lzdGVyLWNoYWxsZW5nZS0xMjM0NTY';
const authChallenge = 'c3ludGhldGljLWF1dGgtY2hhbGxlbmdlLTEyMzQ1Ng';

describe('real browser WebAuthn response verification (no DB)', () => {
  it('verifies registration and the signed discoverable assertion', async () => {
    const result = await completeWebauthnRegistration(config, registration, registerChallenge, user);
    expect(result.error).toBeUndefined(); expect(result.verified).toBe(true); expect(result.draft?.transports).toEqual(['internal']);
    const credential = result.draft!;
    expect((await verifyWebauthnAuthentication(config, assertion, authChallenge, user, credential)).verified).toBe(true);
    expect((await verifyWebauthnAuthentication(config, assertion, 'wrong-challenge', user, credential)).verified).toBe(false);
    expect((await verifyWebauthnAuthentication(config, assertion, authChallenge, { id: 'other-account' }, credential)).verified).toBe(false);
    expect((await verifyWebauthnAuthentication({ ...config, issuer: 'https://wrong.example.test', baseUrl: 'https://wrong.example.test' }, assertion, authChallenge, user, credential)).verified).toBe(false);
    expect((await verifyWebauthnAuthentication(config, assertion, authChallenge, user, { ...credential, counter: 2 })).verified).toBe(false);
  });
});
