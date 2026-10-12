# Contratto — Engine Accounts (OIDC)

> Versione `1.1.0`, estensione additiva della baseline `1.0.0-frozen`.
> Modifiche di protocollo richiedono versionamento e verifiche dei consumatori.
> Compatibilità: PKCE, redirect, scope precedenti, firma JWT, refresh e
> `account.deleted` restano invariati. Le nuove capacità richiedono opt-in del client.

## 1. Ruolo nell'architettura

Engine Accounts è l'**identity provider della suite Engine**. Non sa nulla di StreamingEngine:
nessun dato applicativo o impostazione del consumer. Conosce
*account, sessioni, client, scope, consensi, ruoli e registro servizi*.
Un servizio corrisponde a un'audience e può avere più client. Le sue impostazioni
si modificano esclusivamente nella pagina admin del servizio, non in Accounts.

```
app della suite (relying party + resource server)
   │  Authorization Code + PKCE
   ▼
Engine Accounts ──emette JWT firmati──► app
app valida i JWT localmente via JWKS, senza chiamare il provider a ogni richiesta
```

## 2. Endpoint

| Endpoint | Metodo | Note |
|---|---|---|
| `/.well-known/openid-configuration` | GET | discovery. `issuer` = valore di `OIDC_ISSUER` |
| `/.well-known/jwks.json` | GET | chiavi pubbliche, con `kid`. **Alias** del path nativo del provider |
| `/jwks` | GET | path nativo del provider, stessa chiave |
| `/auth` | GET/POST | authorization endpoint |
| `/token` | POST | token endpoint (authorization_code, refresh_token) |
| `/userinfo` | GET/POST | profilo |
| `/introspect` | POST | **solo client confidenziali** |
| `/revoke` | POST | revoca access/refresh token |
| `/end-session` | GET/POST | logout RP-initiated |
| `/ui/*` | GET/POST | **UI nostra**: login, registrazione, consenso, challenge MFA |
| `/account/*` | GET/POST | **UI nostra**: pannello di gestione account |

La UI è nostra ma serve dallo **stesso origin** del provider: niente redirect su un altro host,
niente cookie cross-site per la sessione di login.

## 3. Scopes

### Base (D2: vivono nel core, non richiedono modifiche al codice)

| Scope | Claim `scope` | Quando |
|---|---|---|
| `openid` | — | obbligatorio per il flusso OIDC |
| `profile` | `name` | nome visualizzato |
| `email` | `email`, `email_verified` | email |
| `offline_access` | — | abilita il refresh token |
| `engine:admin` | `engine_roles` (solo access token) | ruolo amministrativo per l'audience corrente |

### Di servizio (registrati come dati, non come codice)

Un nuovo servizio = righe in `services.engine` e `services.streaming_scopes`, **zero modifiche al core**.

| Scope | Claim `scope` | Cosa abilita nel proxy |
|---|---|---|
| `streaming:catalog` | — | `GET /v1/home`, `/v1/facets`, `/v1/browse/*`, `/v1/search`, `/v1/archive`, `/v1/titles/**` |
| `streaming:playback` | — | `GET /v1/titles/{id}/stream` |
| `streaming:account` | — | `GET/DELETE /v1/me`, `GET /v1/me/progress`, `/v1/me/progress/{id}`, `/v1/me/list`, `/v1/me/list/{id}`, `/v1/me/ratings/{id}`, `POST/GET/DELETE /v1/me/streamingcommunity` |

**Regola di minimo privilegio del middleware:**
- `catalog` e `playback` **non** richiedono alcun account-scope: D6 (modalità anonima).
- Solo gli endpoint `/v1/me/*` richiedono `streaming:account`. **Mancandolo → `403 FORBIDDEN`**, non 401.
- `GET` di sola lettura richiede il minimo; `PUT`/`DELETE` richiedono `streaming:account`.

## 4. Audience e resource indicator

RFC 8707. Ogni client è registrato con il proprio `audience`:

| Client di esempio | `aud` / audience |
|---|---|
| `streamingengine-web` (SPA) | `https://api.engine.local/streaming` |
| `streamingengine-tv` | `https://api.engine.local/streaming` |

Il proxy **rifiuta** un token con `aud` diverso, anche se firmato validamente.

## 5. Claim del token

Access token e ID token portano:

| Claim | Presente in | Note |
|---|---|---|
| `iss` | entrambi | deve essere uguale a `OIDC_ISSUER`, match esatto |
| `sub` | entrambi | **identificatore stabile dell'utente**. UUID opaco. Non cambia mai, non è l'email |
| `aud` | access | stringa o array; deve contenere il `aud` del proxy |
| `exp` | entrambi | validato |
| `iat` | entrambi | validato |
| `nbf` | entrambi | validato |
| `jti` | entrambi | UUID, per replay protection |
| `scope` | access | stringa separata da spazi |
| `client_id` | access | client che ha ottenuto il token |
| `email` | access, id | se `email` scope |
| `email_verified` | access, id | se `email` scope |
| `name` | id | se `profile` scope |
| `amr` | id | metodi di autenticazione, es. `["pwd","otp"]` |

**L'ID token non contiene `scope`.** Usare l'access token per le API.

## 6. Sicurezza del token (non negoziabile)

- **Algoritmi ammessi: `EdDSA` (Ed25519) e `RS256`.** Nessun `none`, nessun `HS*`
  (confusione HS/RS rifiutata a livello di libreria).
- Firma verificata con la JWKS **cacheata** e rinfrescata su chiave sconosciuta, con
  coalescing delle richieste (D1: nessuna chiamata al provider per ogni richiesta).
- TTL access token: **15 minuti**. Refresh token: **30 giorni**, con **rotazione a ogni uso**.
- **Rilevamento del riuso**: un refresh token già usato revoca **l'intera famiglia**.
  I client che ruotano devono gestire il `401` e rifare la sequenza di autorizzazione.
- Chiavi con rotazione: le chiavi vecchie restano pubblicate in JWKS finché non scadono i
  token che hanno firmato. `kid` obbligatorio.

## 7. PKCE e client

- **PKCE `S256` obbligatorio per TUTTI i client**, pubblici e confidenziali. `plain` rifiutato.
- `redirect_uri`: **match esatto**, stringa per stringa. Nessun prefisso, nessun wildcard,
  nessuna tolleranza per query diverse.
- Client pubblici (SPA, mobile, TV): nessun secret. Refresh token **consentito solo con PKCE**.
- Client confidenziali: **secret memorizzato come hash** (argon2id), mai in chiaro.

## 8. Evento di cancellazione account (C11)

Alla cancellazione dell'account, il provider emette un evento **firmato** verso l'URL registrato
nel campo `backchannel_events_uri` del client.

**Payload** (consumato, ad esempio, da `POST /internal/events/account-deleted` di StreamingEngine):

```json
{
  "event": "account.deleted",
  "sub": "<sub stabile>",
  "iss": "http://localhost:8080",
  "aud": "https://api.engine.local/streaming",
  "iat": 1759000000,
  "exp": 1759000300,
  "jti": "<uuid univoco>",
  "signature": "<JWS compatto HS256 sul payload canonico>"
}
```

Il provider **non sa cosa c'è dietro quell'URL**. Il proxy cancella i dati di quel `sub`
e deve essere idempotente (lo stesso `jti` può arrivare più volte).

**Firma:** JWS compatto HS256, payload JSON UTF-8 canonico nei sette campi elencati,
senza signature. Chiave di 32 byte via HKDF-SHA256 dal segreto UTF-8
OIDC_EVENT_SIGNING_SECRET, salt vuoto, info `engine-accounts/backchannel-event-signing`.
Il destinatario deve verificare algoritmo, firma, uguaglianza dei byte al corpo,
issuer/audience, iat/exp e antireplay jti. Il provider invia Origin dell'issuer;
questo header non sostituisce autenticazione e protezioni di rete.
204/altro 2xx = consegnato, 409 = già elaborato e quindi consegnato. Errori restano
nell'outbox. L'interoperabilità va collaudata contro il destinatario effettivo,
non dedotta dalle sole suite separate.

URL di consegna HTTPS; HTTP consentito sul loopback o su origini interne esatte
autorizzate dall'operatore via BACKCHANNEL_HTTP_ALLOWED_ORIGINS. Nessun redirect
seguito. Questa eccezione non rende sicuro HTTP su reti pubbliche/non fidate.

## 9. CLI admin

```
engine-accounts client add <client_id> --type public|confidential \
    --redirect-uri <uri> --post-logout-uri <uri> \
    --scope openid,profile,email,offline_access,streaming:catalog,streaming:playback,streaming:account \
    --audience https://api.engine.local/streaming \
    [--backchannel-events-uri <url>]

engine-accounts user block <sub>          engine-accounts user unblock <sub>
engine-accounts sessions revoke <sub>     engine-accounts keys rotate
engine-accounts user list
engine-accounts user promote <sub> --global
engine-accounts user demote <sub> --global [--force]
engine-accounts service-admin grant <sub> <service>
engine-accounts service-admin revoke <sub> <service>
```

Gli scope base, incluso openid, devono essere registrati esplicitamente: il provider
valida la richiesta contro gli scope del client. Solo scope di servizio non bastano.

## 10. Validazione nel resource server

Middleware di validazione JWT con, in quest'ordine:

1. Header `Authorization` assente → **anonimo** (D6). Nessun errore.
2. Header presente, token non valido (scaduto, `alg:none`, firma rotta, `aud` o `iss` errati)
   → **`401 UNAUTHORIZED`** + `WWW-Authenticate: Bearer error="invalid_token"`.
   **Mai** degradare in silenzio ad anonimo (C2).
3. Token valido ma senza `streaming:account` su un endpoint `/v1/me/*` → `403 FORBIDDEN`.
4. Token valido e scope ok → `sub` disponibile per l'overlay `user` e per la cache con
   `Vary: Authorization` + `Cache-Control: private` (C1).
5. **Isolamento per `sub`**: nessuna query dell'utente A può mai restituire dati di B.

## 11. Ruoli per audience (1.1.0)

`engine:admin` è uno scope base, da registrare esplicitamente e richiedere nel
flusso OIDC. Soltanto un account attivo con tale scope concesso ottiene
`engine_roles` nell'access token: `["admin"]` per un admin assegnato al servizio,
`["admin","global"]` per un admin globale. Nessun ruolo di altre audience viene
rivelato; un utente senza ruolo non riceve il claim. **Non compare nell'ID token**.
Globali e assegnati devono attivare TOTP o passkey per accedere ai pannelli Accounts.
Il bootstrap del primo globale è esclusivamente CLI. L'ultimo globale attivo non
può essere declassato/bloccato/cancellato, salvo `--force` esplicito in CLI.
La UI impedisce modifiche dei propri privilegi. I ruoli si verificano a ogni richiesta.

Il TTL admin è invariato (`ACCESS_TOKEN_TTL`, default 900 secondi). Un JWT già
emesso può restare valido offline fino a `exp`, anche dopo ban o revoca. Non usare
il claim come unica autorizzazione per azioni critiche.

### Verifica server-side

`POST /services/authz`, JSON `{ "sub": "<UUID>", "serviceId": "<id registrato>" }`,
autenticazione HTTP Basic con client **confidenziale** attivo del medesimo servizio
e secret CLI (hash Argon2id nel DB). Non usa cookie/sessioni browser. La route
server-to-server non richiede CSRF del browser; rifiuta richieste con Origin e ha
rate limit. Non inviare il secret nel corpo, URL o log. Client pubblico, servizio
diverso o disabilitato non possono verificare account di un'altra audience.

Risposta autorizzata:
```json
{ "admin": true, "global": false, "status": "active" }
```
Stati: `active`, `blocked`, `deleted`. Account assente viene rappresentato come
`deleted`; admin/global sono falsi per account non attivi. Risorse non autorizzate:
404; autenticazione client invalida: 401; rate limit: 429. Il consumer deve fallire
chiuso se Accounts non è disponibile e ripetere la verifica prima di ogni azione critica.

### Pagina admin e SSO

`adminUrl` è un link al servizio, non un redirect autenticato speciale. Il servizio
avvia Authorization Code + PKCE S256, richiede `engine:admin` e usa la sessione
Accounts per SSO. Per operazioni sensibili usare `max_age=300` (o più restrittivo),
verificare `auth_time`, MFA secondo policy del consumer e l'endpoint authz.
Accounts non rende né duplica i settings del servizio.

## 12. API admin del servizio e purge (1.1.0)

`adminApiUrl` è il destinatario **esatto** del POST server-to-server di purge.
Accounts non espone `/internal`. Se manca l'URL, il purge non è disponibile.
HTTPS fuori loopback; le sole eccezioni HTTP sono le origini esatte in
`BACKCHANNEL_HTTP_ALLOWED_ORIGINS`. Credenziali URL, wildcard e fragment vietati;
nessun redirect seguito; timeout 5 secondi. L'health del consumer è opzionale,
non è implicito nel successo della consegna eventi.

Payload canonico, sette campi in questo ordine, più signature:
```json
{
  "event": "account.data_purge",
  "sub": "<UUID stabile>",
  "iss": "https://accounts.example",
  "aud": "https://service.example/api",
  "iat": 1759000000,
  "exp": 1759000300,
  "jti": "<UUID idempotency key>",
  "signature": "<JWS compatto HS256>"
}
```
Firma JWS HS256 `typ=JWT`, byte UTF-8 di `JSON.stringify({event,sub,iss,aud,iat,exp,jti})`.
Chiave 32 byte HKDF-SHA256, radice UTF-8 `OIDC_EVENT_SIGNING_SECRET`, salt 32 byte
zero (equivalente a salt vuoto HKDF), **info `engine-accounts/service-admin-api`**:
non riusare la chiave di `account.deleted`. Origin dell'issuer è solo informativo.
Verificare alg, firma, corrispondenza byte, issuer/audience, tipi, iat/exp (finestra
massima 300 secondi, tolleranza futura 30 secondi), jti e idempotenza persistente.

**204 = consegnato, 409 = già elaborato e consegnato**, tutti gli altri stati
restano nell'outbox. Retry con lo stesso jti e nuova finestra iat/exp/firma breve.
Il consumer conserva l'idempotency key anche oltre la scadenza del tentativo;
deduplicare prima di ripetere il purge. Purge elimina solo i dati applicativi del
sub in quel servizio, non l'identità Accounts né i ruoli negli altri servizi.
Non confondere l'evento con cancellazione identità o revoca del consenso.

Lato consumer fuori scope: [richieste esatte](../docs/integration/consumer-admin.md).
