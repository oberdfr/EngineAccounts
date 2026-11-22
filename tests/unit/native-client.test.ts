import { describe, expect, it } from 'vitest';
import { nativeCorsAllowed, validateClientApplication } from '../../src/oidc/native-client.js';
import { toClientMetadata } from '../../src/oidc/adapter.js';
import { redirectFormActionsOf, redirectOriginsOf } from '../../src/security/headers.js';
import type { ClientRecord } from '../../src/domain/types.js';
import type { Config } from '../../src/config.js';

const native = (): ClientRecord => ({ clientId: 'native', clientName: 'Native', clientType: 'public',
  clientSecretHash: null, applicationType: 'native', corsOrigins: ['https://localhost'],
  redirectUris: ['streamingengine://auth/callback'], postLogoutRedirectUris: ['streamingengine://'],
  grantTypes: ['authorization_code', 'refresh_token'], responseTypes: ['code'], scope: ['openid', 'offline_access'],
  audience: 'https://api.example', backchannelEventsUri: null, tokenEndpointAuthMethod: 'none', enabled: true,
  createdAt: new Date(), updatedAt: new Date() });

describe('device-flow client policy', () => {
  it('ammette il literal null solo per un client device-flow che lo dichiara', () => {
    const device = { ...native(), redirectUris: [], corsOrigins: ['https://appassets.androidplatform.net', 'null'],
      grantTypes: ['refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'] };
    expect(() => validateClientApplication(device)).not.toThrow();
    expect(nativeCorsAllowed('null', device)).toBe(true);
    expect(nativeCorsAllowed('https://appassets.androidplatform.net', device)).toBe(true);
    expect(nativeCorsAllowed('https://evil.example', device)).toBe(false);
    expect(() => validateClientApplication({ ...native(), corsOrigins: ['null'] })).toThrow();
    expect(nativeCorsAllowed('null', native())).toBe(false);
    expect(redirectOriginsOf([{ ...device, enabled: true }])).toEqual([]);
  });

  it('ammette file:// (webOS 6) solo per un client device-flow che lo dichiara', () => {
    const device = { ...native(), redirectUris: [], corsOrigins: ['null', 'file://'],
      grantTypes: ['refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'] };
    expect(() => validateClientApplication(device)).not.toThrow();
    expect(nativeCorsAllowed('file://', device)).toBe(true);
    expect(nativeCorsAllowed('file://', { ...device, corsOrigins: ['null'] })).toBe(false);
    expect(() => validateClientApplication({ ...native(), corsOrigins: ['file://'] })).toThrow();
    expect(nativeCorsAllowed('file://', native())).toBe(false);
    expect(redirectOriginsOf([{ ...device, enabled: true }])).toEqual([]);
  });

  it('ammette l\'origine reale di webOS 6 (file://<appId>-webos) solo se dichiarata', () => {
    const real = 'file://top.oberdfr.streamingengine.tv-webos';
    const device = { ...native(), redirectUris: [], corsOrigins: ['null', 'file://', real],
      grantTypes: ['refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'] };
    expect(() => validateClientApplication(device)).not.toThrow();
    expect(nativeCorsAllowed(real, device)).toBe(true);
    expect(nativeCorsAllowed('file://other.app-webos', device)).toBe(false);
    expect(() => validateClientApplication({ ...device, corsOrigins: ['file://x/path'] })).toThrow();
    expect(() => validateClientApplication({ ...native(), corsOrigins: [real] })).toThrow();
  });
});

describe('explicit native client policy', () => {
  it('publishes native metadata and a dedicated CORS allowlist', () => {
    expect(toClientMetadata(native(), {} as Config)).toMatchObject({
      application_type: 'native', cors_origins: ['https://localhost'], token_endpoint_auth_method: 'none',
    });
  });
  it('keeps legacy clients web and never infers native from their name', () => {
    const client = { ...native(), applicationType: undefined, corsOrigins: [], redirectUris: ['https://app.example/cb'] };
    expect(toClientMetadata(client, {} as Config).application_type).toBe('web');
    expect(nativeCorsAllowed('https://localhost', client)).toBe(false);
  });
  it.each(['*', 'null', 'http://localhost', 'https://localhost/', 'https://localhost/path',
    'https://*.example', 'https://user:pass@localhost', 'capacitor://localhost'])('rejects CORS origin %s', (origin) => {
    expect(() => validateClientApplication({ ...native(), corsOrigins: [origin] })).toThrow();
  });
  it.each(['javascript:alert(1)', 'data:text/html,hello', 'file:///callback',
    'streamingengine://user@auth/callback', 'streamingengine://auth/callback#x',
    'streamingengine://auth/*', 'https://localhost/cb'])('rejects native redirect %s', (uri) => {
    expect(() => validateClientApplication({ ...native(), redirectUris: [uri] })).toThrow();
  });
  it('requires explicit public native registration and origins', () => {
    expect(() => validateClientApplication({ ...native(), clientType: 'confidential' })).toThrow();
    expect(() => validateClientApplication({ ...native(), corsOrigins: [] })).toThrow();
    expect(() => validateClientApplication({ ...native(), applicationType: 'web' })).toThrow();
  });
  it('binds exact origin per native client, never null, wildcard, suffix or unrelated client', () => {
    expect(nativeCorsAllowed('https://localhost', native())).toBe(true);
    for (const origin of ['null', '*', 'https://localhost.evil', 'http://localhost', 'https://other.example']) {
      expect(nativeCorsAllowed(origin, native())).toBe(false);
    }
    expect(nativeCorsAllowed('https://localhost', { applicationType: 'web', corsOrigins: ['https://localhost'] })).toBe(false);
  });
  it('allows custom scheme only in interaction form actions, never as a CORS origin', () => {
    expect(redirectOriginsOf([native()])).toEqual(['https://localhost']);
    expect(redirectFormActionsOf([native()])).toEqual(['https://localhost', 'streamingengine:']);
    expect(redirectFormActionsOf([{ ...native(), enabled: false }])).toEqual([]);
  });
});
