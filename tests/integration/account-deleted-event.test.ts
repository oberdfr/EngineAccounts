import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  canonicalize,
  verifyAccountDeletedEvent,
  type AccountDeletedEvent,
} from '../../src/services/account-deleted-event.js';
import {
  CONF_CLIENT_ID,
  createTestUser,
  registerTestClientViaCli,
  setupHarness,
  testEnv,
  type Harness,
} from '../helpers/harness.js';

/**
 * C11 — evento di cancellazione dell'account.
 *
 * Il test non controlla solo "e' partito qualcosa": mette in ascolto un
 * back-channel locale, cancella un account e verifica che il payload sia
 * **esattamente** quello del contratto §8 — campi, ordine canonico, firma
 * verificabile con la chiave condivisa.
 */

let h: Harness;
let user: { id: string; email: string; password: string };
let receiver: Server;
let receiverUrl: string;
const received: AccountDeletedEvent[] = [];

beforeAll(async () => {
  h = await setupHarness();
  user = await createTestUser(h, { verified: true });

  // Back-channel finto: accetta l'evento e lo conserva per la verifica.
  receiver = createServer((req: IncomingMessage, res: ServerResponse) => {
    if (req.method !== 'POST') {
      res.writeHead(405).end();
      return;
    }
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      try {
        received.push(JSON.parse(body) as AccountDeletedEvent);
        res.writeHead(204).end();
      } catch {
        res.writeHead(400).end();
      }
    });
  });
  await new Promise<void>((resolve) => receiver.listen(0, '127.0.0.1', resolve));
  const address = receiver.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  receiverUrl = `http://127.0.0.1:${port}/internal/events/account-deleted`;
}, 120_000);

afterAll(async () => {
  await new Promise<void>((resolve) => receiver.close(() => resolve()));
  await h?.close();
});

describe('account.deleted (C11)', () => {
  it('il client senza backchannel non viene disturbato', async () => {
    const before = received.length;
    // `CONF_CLIENT_ID` non ha `backchannel_events_uri`: nessun evento.
    const client = await h.store.findClient(CONF_CLIENT_ID);
    expect(client?.backchannelEventsUri).toBeNull();
    const result = await h.accounts.deleteAccount(user.id, { password: user.password }, { ip: null, userAgent: null });
    expect(result.ok).toBe(true);
    expect(received.length).toBe(before);
  });

  it('emette l\'evento firmato al client con backchannel_events_uri', async () => {
    // Un secondo utente, per non dipendere dall'ordine dei test.
    const target = await createTestUser(h, { verified: true });
    // Il client si registra **via CLI**: e' il percorso che la DoD vuol provare, e
    // la CLI fa l'hashing del secret come si deve.
    const registered = registerTestClientViaCli(testEnv(), [
      'client',
      'add',
      'proxy-destinatario',
      '--type',
      'confidential',
      '--redirect-uri',
      'https://proxy.example.test/cb',
      '--audience',
      h.config.OIDC_AUDIENCE,
      '--scope',
      'openid,profile',
    ]);
    expect(registered.status, registered.stdout).toBe(0);
    // La CLI accetta solo https per il back-channel (C11): qui il destinatario
    // e' in chiaro su localhost, quindi puntiamo la colonna al ricevitore
    // locale. E' l'unica riga che il test tocca a mano, e non riguarda la
    // sicurezza dell'evento (che e' verificata subito sotto).
    await h.db.query(
      `UPDATE "engine_accounts_test"."clients" SET backchannel_events_uri = $1 WHERE client_id = 'proxy-destinatario'`,
      [receiverUrl],
    );

    const result = await h.accounts.deleteAccount(target.id, { password: target.password }, { ip: null, userAgent: null });
    expect(result.ok).toBe(true);

    expect(received.length, 'il back-channel deve aver ricevuto un evento').toBe(1);
    const event = received[0]!;

    // 1. campi e valori, esattamente come il contratto §8.
    expect(Object.keys(event).sort()).toEqual(
      ['aud', 'event', 'exp', 'iat', 'iss', 'jti', 'signature', 'sub'].sort(),
    );
    expect(event.event).toBe('account.deleted');
    expect(event.sub).toBe(target.id);
    expect(event.iss).toBe(h.config.issuer);
    expect(event.aud).toBe(h.config.OIDC_AUDIENCE);
    expect(typeof event.iat).toBe('number');
    expect(typeof event.exp).toBe('number');
    expect(event.exp).toBeGreaterThan(event.iat);
    expect(event.jti).toMatch(/^[0-9a-f-]{36}$/);
    expect(typeof event.signature).toBe('string');

    // 2. firma verificabile con la chiave condivisa, sul payload canonico.
    const verified = await verifyAccountDeletedEvent(event, h.config.eventSigningKey, {
      iss: h.config.issuer,
      aud: h.config.OIDC_AUDIENCE,
    });
    expect(verified.valid, verified.valid ? '' : verified.reason).toBe(true);

    // Il testo firmato e' esattamente la serializzazione canonica: chi verifica
    // (il proxy) deve poterla ricostruire senza conoscere il nostro codice.
    const payload = {
      event: event.event,
      sub: event.sub,
      iss: event.iss,
      aud: event.aud,
      iat: event.iat,
      exp: event.exp,
      jti: event.jti,
    } as const;
    const { compactVerify } = await import('jose');
    const { payload: signed } = await compactVerify(event.signature, h.config.eventSigningKey, {
      algorithms: ['HS256'],
    });
    expect(new TextDecoder().decode(signed)).toBe(canonicalize(payload));
    // La ricostruzione indipendente: il proxy serializza nello stesso ordine.
    expect(canonicalize(payload)).toBe(
      JSON.stringify({
        event: 'account.deleted',
        sub: target.id,
        iss: h.config.issuer,
        aud: h.config.OIDC_AUDIENCE,
        iat: event.iat,
        exp: event.exp,
        jti: event.jti,
      }),
    );
  });

  it('un evento manomesso o firmato male viene rifiutato', async () => {
    const event = received[0]!;
    const key = h.config.eventSigningKey;

    const base = { iss: h.config.issuer, aud: h.config.OIDC_AUDIENCE };

    // sub alterato: la firma non copre piu' il payload.
    const forged = await verifyAccountDeletedEvent({ ...event, sub: '00000000-0000-0000-0000-000000000000' }, key, base);
    expect(forged.valid).toBe(false);

    // jti riusato ma scaduto: scadenza corta.
    const expired = await verifyAccountDeletedEvent({ ...event, exp: event.iat - 10 }, key, base);
    expect(expired.valid).toBe(false);

    // issuer non riconosciuto.
    const wrongIss = await verifyAccountDeletedEvent(event, key, { iss: 'https://altro.example' });
    expect(wrongIss.valid).toBe(false);

    // audience diversa da quella del proxy destinatario.
    const wrongAud = await verifyAccountDeletedEvent(event, key, { ...base, aud: 'https://altro.example' });
    expect(wrongAud.valid).toBe(false);

    // chiave sbagliata.
    const wrongKey = await verifyAccountDeletedEvent(event, Buffer.alloc(32, 7), base);
    expect(wrongKey.valid).toBe(false);
  });

  it('l\'account cancellato non e\' piu\' utilizzabile', async () => {
    const target = await h.store.findUserById(user.id);
    expect(target?.status).toBe('deleted');
    // `sub` stabile: la riga resta, i dati no.
    expect(target?.id).toBe(user.id);
    expect(target?.email).toMatch(/^deleted\+/);
    expect(target?.displayName).toBeNull();
    // E il login non e' piu' possibile.
    const outcome = await h.accounts.authenticate(target?.email ?? '', user.password, { ip: null, userAgent: null });
    expect(outcome.status).not.toBe('ok');
  });
});