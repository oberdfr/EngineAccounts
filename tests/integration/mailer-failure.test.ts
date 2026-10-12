import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  HttpClient,
  createTestUser,
  setupHarness,
  type Harness,
} from '../helpers/harness.js';
import type { Mailer, MailMessage } from '../../src/services/mailer.js';

/**
 * La registrazione non dipende dalla posta.
 *
 * Quando l'SMTP non risponde, l'utente e' comunque nel database e il token di
 * verifica e' valido: rispondere 500 sarebbe sbagliato due volte. La prima per
 * che' l'account esiste gia' e un 500 fa credere che la registrazione sia
 * fallita; la seconda perche' romperebbe la risposta neutra, che e' l'unica
 * cosa che tiene l'anti-enumerazione: se "posta giù" e "email gia' registrata"
 * dessero risposte diverse, l'endpoint diventerebbe un oracle.
 *
 * Non e' ipotetico: in sviluppo `SMTP_HOST=mailpit` (il nome di rete del
 * container) non risolve fuori dal compose, e `POST /ui/register` rispondeva 500.
 */

let h: Harness;

/** Mailer che fallisce sempre, come un SMTP irraggiungibile. */
class BrokenMailer implements Mailer {
  readonly attempts: MailMessage[] = [];
  async send(message: MailMessage): Promise<void> {
    this.attempts.push(message);
    throw new Error('getaddrinfo ENOTFOUND mailpit');
  }
}

const broken = new BrokenMailer();

beforeAll(async () => {
  h = await setupHarness({ mailer: broken });
}, 120_000);

afterAll(async () => {
  await h?.close();
});

describe('registrazione con SMTP irraggiungibile', () => {
  it('risponde il 303 neutro e crea lo stesso l\'utente', async () => {
    const client = new HttpClient(h.baseUrl);
    const email = `no-smtp-${Date.now()}@example.test`;

    const csrf = await client.csrfFrom('/ui/register');
    const res = await client.postForm('/ui/register', {
      _csrf: csrf,
      email,
      displayName: 'Utente Senza SMTP',
      password: 'PasswordLungaCheNonEsiste123!',
    });

    // Non un 500: la stessa risposta di sempre, cosi' l'anti-enumerazione regge.
    expect(res.status, 'la risposta deve essere la neutra, non un errore').toBe(303);
    expect(res.headers.get('location') ?? '').toContain('/ui/register?sent=1');

    // E l'utente c'e' davvero, e l'invio e' stato tentato.
    const user = await h.store.findUserByEmail(email);
    expect(user?.email, 'l\'account deve essere stato creato').toBe(email);
    expect(broken.attempts, 'l\'invio deve essere stato tentato').toHaveLength(1);
  }, 60_000);

  it('risponde identico anche per un\'email gia\' registrata', async () => {
    const email = `no-smtp-dup-${Date.now()}@example.test`;
    const client = new HttpClient(h.baseUrl);

    const first = await client.postForm('/ui/register', {
      _csrf: await client.csrfFrom('/ui/register'),
      email,
      password: 'PasswordLungaCheNonEsiste123!',
    });
    const second = await client.postForm('/ui/register', {
      _csrf: await client.csrfFrom('/ui/register'),
      email,
      password: 'PasswordLungaCheNonEsiste123!',
    });

    // Le due risposte devono essere indistinguibili: e' questo il punto.
    expect(first.status).toBe(303);
    expect(second.status).toBe(303);
    expect(first.headers.get('location')).toBe(second.headers.get('location'));
  }, 60_000);

  it('l\'invio fallito lascia una traccia in audit', async () => {
    const email = `audit-smtp-${Date.now()}@example.test`;
    const client = new HttpClient(h.baseUrl);
    await client.postForm('/ui/register', {
      _csrf: await client.csrfFrom('/ui/register'),
      email,
      password: 'PasswordLungaCheNonEsiste123!',
    });

    const user = await h.store.findUserByEmail(email);
    expect(user?.id, 'l\'utente deve esistere').toBeTruthy();
    const entries = await h.store.listAudit(user!.id, 50);
    const failure = entries.find((e) => e.event === 'email.send_failed');
    expect(failure, 'il fallimento di invio deve finire in audit').toBeTruthy();
    expect(failure?.outcome).toBe('failure');
  }, 60_000);

  it('il login di un utente verificato funziona anche se la posta e\' rotta', async () => {
    // Se la posta fosse un prerequisito, un utente gia' esistente non potrebbe
    // nemmeno autenticarsi: il login non passa dall'SMTP.
    const user = await createTestUser(h, { verified: true });
    const outcome = await h.accounts.authenticate(user.email, user.password, {
      ip: null,
      userAgent: null,
    });
    expect(outcome.status, 'il login non deve dipendere dalla posta').toBe('ok');
  });
});