# Richieste per i consumer — contratto 1.1.0

Questo task modifica soltanto Accounts. Nessuna modifica a StreamingEngine o ad
altri consumer è inclusa. Fonte autorevole: [contratto](../../contracts/oidc.md), §11–12.

## Registrazione

Un'audience = un servizio, uno o più client. Registrare `engine:admin` tra gli
scope consentiti; un client pubblico per SSO e un client confidenziale per authz
possono condividere l'audience. Registrare `serviceId`, nome, descrizione,
`adminUrl` (pagina admin) e `adminApiUrl` (destinatario esatto del purge).
Non usare un secret di client pubblico né distribuirlo al browser.

## Pagina admin

1. Avviare il proprio flusso OIDC code/PKCE S256, redirect esatto, state/nonce,
   scope `openid engine:admin`, `max_age=300` per autenticazione recente.
2. Validare access JWT via JWKS (`EdDSA`/`RS256`, issuer, audience, tempo).
3. Richiedere `engine:admin` nello scope e `admin` in `engine_roles` nell'access
   token; non cercare il ruolo nell'ID token. `global` non sostituisce `admin`.
4. Prima delle azioni critiche chiamare `POST <issuer>/services/authz`, Basic
   clientId/secret, JSON `{sub, serviceId}`. Ammesso solo `admin=true` e
   `status=active`; indisponibilità/errore/revoca devono negare l'operazione.
5. Implementare CSRF, conferma, ri-verifica e audit nel proprio pannello. Tutte
   le impostazioni del servizio restano lì, Accounts offre soltanto il link SSO.

## Ricezione purge

Implementare POST all'`adminApiUrl` registrato, solo lato server. Il formato
completo è quello di §12; non sono aggiunti path o suffissi automaticamente.
La firma è JWS compatto nel campo `signature`; non un Bearer HTTP.

Derivazione:
```
key = HKDF-SHA256(UTF8(OIDC_EVENT_SIGNING_SECRET), salt=32 zero bytes,
                  info=UTF8("engine-accounts/service-admin-api"), length=32)
canonical = UTF8(JSON.stringify({event, sub, iss, aud, iat, exp, jti}))
```
Verificare esclusivamente HS256 e i byte canonici, event `account.data_purge`,
issuer/audience attesi e finestra temporale valida (max 300s; futuro max 30s).
Non usare la JWKS per questa firma né la chiave HKDF degli eventi di cancellazione.
Limitare dimensione corpo, applicare policy rete/TLS e non loggare firma/corpo.

In una transazione idempotente, eliminare tutti i dati di quel sub nel servizio
e registrare il jti elaborato. Rispondere 204 solo a completamento effettivo;
409 per jti già completato. Non marcare come completata una richiesta fallita.
I retry conservano jti ma rinnovano iat/exp e firma. Gli altri status (inclusi 200,
202 e redirect) non confermano il purge ad Accounts.

Non eliminare account Accounts, dati di altre audience o impostazioni servizio.
Il vecchio `account.deleted` resta supportato con la sua derivazione e formato.
Testare firma errata/scaduta, audience diversa, replay, retry e isolamento sub
contro un emitter isolato: suite separate non dimostrano interoperabilità.

## Limiti

Nessuna revoca JWT offline istantanea: TTL admin invariato, default 15 minuti.
L'health sintetico del consumer è opzionale e non implementato da questo contratto
di purge. Non presentare un servizio come sano solo perché è registrato.
