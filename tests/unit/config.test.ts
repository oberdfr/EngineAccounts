import { describe, expect, it } from 'vitest';
import { loadConfig, databaseUrlFromPostgresEnv } from '../../src/config.js';
import { testEnv } from '../helpers/harness.js';

/**
 * Il percorso di sviluppo documentato e' `npm run dev` **senza esportare
 * nessuna variabile**. Prima che il `.env` della radice venisse caricato, il
 * servizio partiva con un default sbagliato (porta 5432, password `engine`) e
 * moriva con `ECONNREFUSED`, mentre sotto compose funzionava: due comportamenti
 * diversi per lo stesso servizio.
 *
 * Qui si verifica la composizione della `DATABASE_URL` e la precedenza delle
 * variabili gia' presenti sull'ambiente.
 */

describe('issuer: la trappola del 401 silenzioso', () => {
  /**
   * `OIDC_ISSUER` finisce nel claim `iss` di ogni token e i consumer lo
   * confrontano. Se resta `localhost` mentre il frontend e' sul dominio, qui
   * non si vede niente di rotto e il fallimento arriva dall'altra parte, come
   * 401 su ogni richiesta. In produzione il servizio rifiuta di partire.
   */
  const produzione = { NODE_ENV: 'production', OIDC_EVENT_SIGNING_SECRET: 'x', ENGINE_ACCOUNTS_COOKIE_SECRET: 'y' };

  it('rifiuta di avviarsi in produzione con issuer di loopback', () => {
    for (const issuer of ['http://localhost:8080', 'http://127.0.0.1:8080', 'http://[::1]:8080']) {
      expect(
        () => loadConfig({ ...produzione, OIDC_ISSUER: issuer, DATABASE_URL: 'postgres://a:b@h/db' } as NodeJS.ProcessEnv),
        `issuer ${issuer} doveva essere rifiutato`,
      ).toThrow(/OIDC_ISSUER/);
    }
  });

  it('in produzione accetta il dominio', () => {
    const config = loadConfig({
      ...produzione,
      OIDC_ISSUER: 'https://account.oberdfr.top',
      PUBLIC_BASE_URL: 'https://account.oberdfr.top',
      DATABASE_URL: 'postgres://a:b@h/db',
    } as NodeJS.ProcessEnv);
    expect(config.issuer).toBe('https://account.oberdfr.top');
    expect(config.secureCookies).toBe(true);
    // Disattivato di default perche' oidc-provider imposta ea_res con path scopato incompatibile con __Host-
    expect(config.cookiePrefix).toBe('');
  });

  it('in sviluppo l\'issuer di loopback e\' la scelta giusta', () => {
    const config = loadConfig({
      NODE_ENV: 'development',
      OIDC_ISSUER: 'http://localhost:8080',
      DATABASE_URL: 'postgres://a:b@h/db',
    } as NodeJS.ProcessEnv);
    expect(config.issuer).toBe('http://localhost:8080');
  });
});

describe('HSTS e proxy', () => {
  it('HSTS e\' spento di default e TRUST_PROXY idem', () => {
    const config = loadConfig({ ...testEnv() } as NodeJS.ProcessEnv);
    expect(config.hsts.enabled).toBe(false);
    expect(config.TRUST_PROXY).toBe(false);
  });

  it('i cookie diventano Secure con issuer https, mentre __Host- richiede opt-in esplicito', () => {
    const conDominio = loadConfig({
      ...testEnv(),
      OIDC_ISSUER: 'https://account.oberdfr.top',
    } as NodeJS.ProcessEnv);
    expect(conDominio.cookiePrefix).toBe('');
    expect(conDominio.secureCookies).toBe(true);

    // Su http i cookie non sono Secure.
    const suHttp = loadConfig({ ...testEnv(), COOKIE_SECURE: 'false' } as NodeJS.ProcessEnv);
    expect(suHttp.cookiePrefix).toBe('');
    expect(suHttp.secureCookies).toBe(false);

    // Con COOKIE_HOST_PREFIX esplicito il prefisso viene abilitato.
    const conPrefisso = loadConfig({
      ...testEnv(),
      OIDC_ISSUER: 'https://account.oberdfr.top',
      COOKIE_HOST_PREFIX: 'true',
    } as NodeJS.ProcessEnv);
    expect(conPrefisso.cookiePrefix).toBe('__Host-');
    expect(conPrefisso.secureCookies).toBe(true);
  });
});

describe('composizione della DATABASE_URL', () => {
  it('la compone da POSTGRES_* quando manca', () => {
    const url = databaseUrlFromPostgresEnv({
      POSTGRES_PASSWORD: 'engine_dev_password',
      POSTGRES_PORT: '55432',
    });
    expect(url).toBe('postgres://engine:engine_dev_password@127.0.0.1:55432/engine');
  });

  it('non indovina nulla se non c\'e\' né DATABASE_URL né POSTGRES_PASSWORD', () => {
    expect(databaseUrlFromPostgresEnv({})).toBeUndefined();
  });

  it('rispetta DATABASE_URL quando arriva gia\' pronta (come fa compose)', () => {
    const url = databaseUrlFromPostgresEnv({
      DATABASE_URL: 'postgres://engine:secret@postgres:5432/engine',
      POSTGRES_PASSWORD: 'engine_dev_password',
      POSTGRES_PORT: '55432',
    });
    expect(url).toBe('postgres://engine:secret@postgres:5432/engine');
  });

  it('codifica la password: una con caratteri speciali non rompe la URL', () => {
    const url = databaseUrlFromPostgresEnv({ POSTGRES_PASSWORD: 'a@b:c/d' });
    expect(url).toBe('postgres://engine:a%40b%3Ac%2Fd@127.0.0.1:5432/engine');
  });

  it('loadConfig usa la URL composta dal .env di sviluppo', () => {
    const config = loadConfig({
      ...testEnv(),
      DATABASE_URL: undefined,
      POSTGRES_PASSWORD: 'engine_dev_password',
      POSTGRES_PORT: '55432',
    } as NodeJS.ProcessEnv);
    expect(config.DATABASE_URL).toBe('postgres://engine:engine_dev_password@127.0.0.1:55432/engine');
  });

  it('loadConfig fallisce in modo leggibile se manca tutto', () => {
    expect(() =>
      loadConfig({
        NODE_ENV: 'development',
        OIDC_EVENT_SIGNING_SECRET: 'x',
      } as NodeJS.ProcessEnv),
    ).toThrow(/DATABASE_URL/);
  });
});