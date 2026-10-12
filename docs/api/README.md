# Engine Accounts — identità e gestione account

Provider OIDC indipendente dai servizi della suite, porta **8080**, issuer pubblico
`https://engine.oberdfr.top`. Conosce account, sessioni, client, scope e consensi;
non contiene catalogo, dati di visione o password SC. Registrare un nuovo client
non richiede codice specifico del frontend.

Riferimenti: [contratto OIDC](../../contracts/oidc.md),
[sicurezza](../security/README.md), [operazioni](../operations/README.md),
[test](../testing/README.md).

## Funzionalità e confini

- Registrazione email/password, verifica email, login, reset password e magic code.
- MFA TOTP, recovery code e WebAuthn; verifiche nel contesto dell'interazione OIDC.
- Profilo/nome/email, password, MFA/passkey, sessioni, consensi app, attività,
  export JSON e cancellazione account dal pannello same-origin.
- Authorization Code + PKCE S256 per client pubblici e confidenziali; access token
  JWT EdDSA/RS256, refresh con rotazione/reuse detection, discovery/JWKS.
- Claim in base a scope, audience/resource indicator, client secret hash Argon2id.
- Evento account.deleted firmato verso backchannel_events_uri registrati.
- CLI per registrare/disabilitare client, bloccare utenti, revocare sessioni,
  ruotare chiavi; nessun endpoint pubblico di amministrazione per servizio.

`src/oidc/provider.ts` configura oidc-provider; adapter DB in src/oidc/adapter.ts.
Dominio e persistenza parlano con AccountsStore/OidcTokenStore in src/db/repositories.ts.
AccountService, SessionManager, MFA/challenge/mailer in src/services/;
password/CSRF/rate limit/breached checks in src/security/; pagine/asset in src/ui/.
Non eliminare asset statici perché non importati da TypeScript: li carica l'HTML.

## API OIDC

| Endpoint | Metodo | Funzione |
|---|---|---|
| /.well-known/openid-configuration | GET | Discovery; issuer esatto e endpoint supportati |
| /jwks, /.well-known/jwks.json | GET | Chiavi pubbliche con kid, mai chiavi private |
| /auth | GET/POST | Autorizzazione; redirect esatto, PKCE S256, state/nonce client, consent/MFA |
| /token | POST | authorization_code o refresh_token; encoding form OAuth |
| /userinfo | GET/POST | Bearer access token, claim consentiti dagli scope |
| /introspect | POST | Solo client confidenziali autorizzati |
| /revoke | POST | Revoca access/refresh token |
| /end-session | GET/POST | RP-initiated logout; id_token_hint e redirect registrato, conferma/POST CSRF |
| /healthz, /readyz | GET | Liveness/readiness, non prova del flusso browser completo |

Non utilizzare queste route come form JSON della SPA. Seguire discovery e libreria
OIDC, con client registrato e browser di sistema su native. `token_type` bearer
è case-insensitive. Scope del client devono includere openid esplicitamente.
Per refresh chiedere offline_access e **prompt=consent**; il campo refresh_token
può altrimenti mancare senza errore. Refresh concorrenti devono essere serializzati.

Access token contiene iss/sub/aud/tempo/scope/client_id e claim email soltanto con
scope email e account attivo. Nome profile è per ID token/userinfo, non identità
autorizzativa. resourceServerFor mantiene scope core e servizio durante refresh.
`src/oidc/userinfo.ts` verifica JWT con JWKS locale e scope: non usa l'handler
userinfo nativo della libreria che rifiuta token con audience resource-server.

## Route UI e pannello

Le UI sono HTML stesso origin, session cookie e POST CSRF; non API mobili di
password grant. Pending/errore/hint dei form e redirect sono parte del flusso.
Form layout scuro con asset locali; schermate separate per autenticazione,
consenso/MFA e gestione account. Navigazione pannello verso profilo, sicurezza,
sessioni, app, attività ed export/cancellazione. Non portare cookie Engine nella SPA.

| Route | Metodo | Ruolo |
|---|---|---|
| /ui/login | GET/POST | Login browser |
| /ui/register | GET/POST | Registrazione e invio verifica |
| /ui/forgot-password | GET/POST | Richiesta reset con risposta neutra |
| /ui/reset-password | GET/POST | Reset con token valido |
| /ui/magic-code | GET/POST | Richiesta codice login |
| /ui/magic-code/verify | POST | Verifica codice e sessione |
| /ui/verify-email | GET | Consumo token verifica/cambio email |
| /ui/interaction/:uid | GET | Interazione richiesta da oidc-provider |
| /ui/interaction/:uid/login | POST | Login per richiesta OIDC |
| /ui/interaction/:uid/mfa | GET/POST | Challenge secondo fattore |
| /ui/interaction/:uid/mfa/options | GET | Opzioni WebAuthn per challenge |
| /ui/interaction/:uid/consent | POST | Registrazione grant scope/resource approvati |
| /ui/webauthn/register/options | POST | Opzioni registrazione secondo flusso supportato |
| /ui/webauthn/register/verify | POST | Verifica attestazione/credenziale |
| /ui/webauthn/register/challenge | POST | Challenge protetto del flusso registrazione |
| /account | GET | Profilo e stato identità |
| /account/security | GET | Password/MFA/passkey/recovery |
| /account/sessions | GET | Sessioni e revoche |
| /account/apps | GET | Consensi/client autorizzati |
| /account/activity | GET | Attività account |
| /account/export | GET | Pagina export |
| /account/export.json | GET | Export dati dell'utente autenticato |
| /account/delete | GET/POST | Conferma/cancellazione con verifica credenziali |
| /account/logout | POST | Logout pannello |
| /account/profile/name | POST | Cambia nome |
| /account/profile/email | POST | Avvia cambio email/verifica |
| /account/security/password | POST | Cambio password |
| /account/security/totp/setup | GET | Setup TOTP nella sessione |
| /account/security/totp/confirm | POST | Conferma codice attivazione |
| /account/security/totp/disable | POST | Disabilitazione protetta |
| /account/security/webauthn/register | GET | Pagina nuova passkey |
| /account/security/webauthn/verify | POST | Verifica registrazione passkey |
| /account/security/webauthn/delete | POST | Elimina credenziale propria |
| /account/security/recovery-codes | POST | Rigenera recovery code |
| /account/sessions/revoke | POST | Revoca sessione propria selezionata |
| /account/sessions/revoke-all | POST | Revoca sessioni secondo policy del servizio |
| /account/apps/revoke | POST | Revoca consenso/app propria |
| /ui/deleted | GET | Conferma account cancellato |

Fonte form/validazioni: src/ui/ui-routes.ts e account-routes.ts. Token verifica,
CSRF, challenge, password e recovery code non vanno salvati in URL diagnostiche,
log o fixture pubbliche. Account bloccato/cancellato non ottiene nuova sessione.
Mail fallita mantiene risposta neutra e audit, non finge email consegnata.

## Configurazione

Fonte di tutti i default/vincoli: **src/config.ts**. server.ts e CLI caricano .env
root, ambiente esplicito ha precedenza. Non stampare config completa con segreti.

| Gruppo | Configurazione |
|---|---|
| Rete | HOST (default 0.0.0.0), PORT (8080), ENGINE_ACCOUNTS_PORT precede PORT; TRUST_PROXY false |
| Identità | OIDC_ISSUER default localhost:8080, PUBLIC_BASE_URL default issuer, OIDC_AUDIENCE default https://api.engine.local/streaming |
| Client pubblici | OIDC_CLIENTS_JSON, default []; registrazione dichiarativa di URI, audience, scope e backchannel prima dell'avvio OIDC |
| Trasporto eventi | HTTPS fuori dal loopback; BACKCHANNEL_HTTP_ALLOWED_ORIGINS permette origini HTTP interne esatte autorizzate, redirect rifiutati |
| DB | DATABASE_URL obbligatoria o composta da POSTGRES_*; DB_SCHEMA engine_accounts, DB_POOL_MAX 10, DB_SSL false |
| Chiavi | OIDC_EVENT_SIGNING_SECRET e ENGINE_ACCOUNTS_COOKIE_SECRET obbligatori in produzione; ENGINE_ACCOUNTS_DATA_KEY o derivazione HKDF; ENGINE_ACCOUNTS_JWKS_PATH var/jwks.json |
| Cookie | COOKIE_SECURE derivato da issuer, COOKIE_HOST_PREFIX false; niente prefisso automatico __Host- su cookie resume scoped |
| HSTS | HSTS_ENABLED false, HSTS_MAX_AGE 31536000, HSTS_INCLUDE_SUBDOMAINS false |
| Scadenze secondi | ACCESS_TOKEN_TTL/ID_TOKEN_TTL 900, REFRESH_TOKEN_TTL 2592000, SESSION_TTL 1209600, CONSENT_TTL 31536000 |
| Challenge secondi | PASSWORD_RESET_TTL/EMAIL_VERIFICATION_TTL/EMAIL_CHANGE_TTL 900, MAGIC_CODE_TTL 300 |
| Password | PASSWORD_MIN_LENGTH 12, PASSWORD_MAX_LENGTH 1024; ARGON2_MEMORY_KIB 65536, ARGON2_ITERATIONS 3, ARGON2_PARALLELISM 1 |
| Limiti | HTTP_LOGIN_SLOW_MS 200, LOGIN_RATE_IP_MAX 40/5 min, LOGIN_RATE_ACCOUNT_MAX 8/15 min; lock progressivo ACCOUNT_LOCK_BASE_MS/MAX_MS; reset/registrazione 5/ora |
| Breached check | HIBP_ENABLED true, HIBP_API_BASE, HIBP_TIMEOUT_MS 1500, HIBP_CACHE_TTL_MS 86400000 |
| Posta | SMTP_HOST/PORT/USER/PASSWORD/FROM/FROM_NAME/SECURE, MAIL_ENABLED; SMTP default 127.0.0.1:1025 |

HTTPS pubblico dietro ingress richiede TRUST_PROXY e forwarding affidabile;
CSP consenso deriva origini dai redirect dei client attivi; logout soltanto
dal post_logout_redirect_uri validato. Nessun wildcard o allowlist hardcoded
per nuovi client. Accounts non espone route /internal: backchannel è in uscita.

## Registrare un client e CLI

Esempio per un **nuovo ambiente/client autorizzato**, dalla directory Accounts:
```bash
npm run cli -- client add streamingengine-web --type public \
  --redirect-uri http://localhost:5173/auth/callback \
  --post-logout-uri http://localhost:5173/ \
  --scope openid,profile,email,offline_access,streaming:catalog,streaming:playback,streaming:account \
  --audience https://api.engine.local/streaming
npm run cli -- client list
```
client add aggiorna anche una registrazione esistente: non usarlo su produzione
come verifica innocua. URI localhost/127.0.0.1 e porte diverse non sono equivalenti.
App mobile: client pubblico dedicato, redirect compatibile con OS e validazione
provider; nessun secret incorporato. Servizi aggiuntivi registrano dati di scope
e audience invece di aggiungere logica prodotto al core OIDC.

| Comando | Effetto |
|---|---|
| client add <id> | registra/aggiorna; --type, --redirect-uri, --post-logout-uri, --scope, --audience, --name, --backchannel-events-uri |
| client add <id> --rotate | ruota secret client confidenziale, mostrato una volta e memorizzato hash |
| client list | elenco registrazioni |
| client remove <id> | elimina la registrazione e i consensi collegati per cascata; non revoca istantaneamente JWT verificati offline |
| user block <sub> / user unblock <sub> | blocca/riattiva account |
| sessions revoke <sub> | revoca sessioni utente |
| keys rotate | nuova Ed25519 prima nel JWKS, conserva precedente; restart controllato necessario |

sub UUID stabile, non email. Evento account.deleted: JWS compatto HS256 sul JSON
canonico, con chiave HKDF come contratto e URL registrato. StreamingEngine accetta
questo formato e verifica audience, issuer, tempo e replay; Origin deriva dall'issuer.
204 o 409 significano consegna completata; gli altri errori restano nell'outbox.
Non è API di cancellazione per la SPA. La cancellazione identità è distinta da
DELETE /v1/me del proxy, che elimina soltanto dati del servizio.

## Logout RP-initiated

ID token hint ancora in memoria, state e post_logout_redirect_uri registrato;
provider valida token/client/redirect e legame sessione (sub, grant, auth_time,
sid quando presente). Auto-submit del form originale solo con tali prove;
altrimenti conferma breve. /static/logout.js mantiene xsrf e submitter logout=yes.
Revocare refresh/access token prima di end-session conserva il legame grant della
sessione necessario alla verifica. Senza JavaScript resta il pulsante Continua.
Non implementare un parametro confirmed che salta queste verifiche.

## Esecuzione, test e dati

```bash
npm run typecheck
npm test
npm run build
npm start
```
Dev `npm run dev`, migrazioni `npm run migrate`, test unit/integration/security
separati. Non avviare un duplicato sulla porta pubblica. Integration usa schema
dedicato engine_accounts_test e JWKS test: [test](../testing/README.md).
Backup/restore richiede DB + JWKS private + chiavi config coerenti:
[operazioni](../operations/README.md). Non cambiare issuer per far passare test.
Dockerfile/compose sono opzioni di installazione su ambiente dedicato; stack
pubblico corrente usa systemd e container infra esistenti.
