# Configurazione e operazioni EngineAccounts

## Configurazione unica

`.env` nella root del checkout, caricato da `src/env.ts` da src/ e dist/. Non cerca
file in StreamingEngine o nel parent. Le variabili di processo esplicite prevalgono.
Tutti i default/vincoli sono in `src/config.ts`; inventario in [API](../api/README.md).

Policy amministrabili: precedenza **env esplicito > override DB > default**.
L'origine e il valore effettivo sono visibili in `/admin/settings`; un valore
bloccato da env non cambia tramite UI. I segreti, issuer, DB, SMTP e materiale
JWKS non sono modificabili da pannelli. `invite` chiude la registrazione libera:
finché non è disponibile un flusso d'invito, gli operatori non devono prometterne
la creazione tramite UI. I pannelli admin richiedono sempre TOTP/passkey.
Il TTL effettivo si applica alle nuove sessioni e come limite durante la
risoluzione delle sessioni esistenti. Una riduzione può quindi renderle non più
valide anche prima della scadenza memorizzata; la UI mostra quel limite effettivo.
L'outbox ritenta fino a 20 eventi ogni 30 secondi, senza seguire redirect.

## Aggiornamento 1.1.0 (da eseguire dall'operatore, non da questo task)

1. Backup protetto DB, `.env` e JWKS senza modificare segreti o issuer.
2. Revisionare le nuove migrazioni additive e il contratto consumer §11–12.
3. `npm ci`, `npm run typecheck`, test su `engine_accounts_test`,
   `node scripts/check-config.mjs` (non stampa valori).
4. `./scripts/rebuild.sh` compila e riavvia solo Accounts; l'avvio applica le
   migrazioni nel DB_SCHEMA configurato. Non avviare un secondo processo su 8080.
5. Bootstrap su sub esistente con `npm run cli -- user promote <sub> --global`;
   l'utente attiva TOTP/passkey prima di aprire `/admin`.
6. Configurare per servizio gli URL e gli scope come dati (env/CLI). Coordinare
   separatamente il rilascio consumer: il purge non è operativo senza ricevitore.
7. Verificare login, ri-verifica admin, ruoli, consegna outbox e invii SMTP;
   readiness da sola non prova questi flussi. Nessun reset DB/container necessario.

Per produzione impostare NODE_ENV=production, OIDC_ISSUER e PUBLIC_BASE_URL sullo
stesso dominio HTTPS, DATABASE_URL, OIDC_EVENT_SIGNING_SECRET, ENGINE_ACCOUNTS_COOKIE_SECRET,
SMTP raggiungibile e mittente autorizzato. TRUST_PROXY=true solo dietro ingress
fidato. HSTS su HTTPS, COOKIE_HOST_PREFIX=false per cookie resume scoped.
I client pubblici arrivano da OIDC_CLIENTS_JSON (JSON su una sola riga); si applicano
senza CLI prima del provider. URI esatte, audience coerente col consumer, scope openid.
Backchannel richiede HTTPS fuori dal loopback; per una rete HTTP privata deliberatamente
fidata usare BACKCHANNEL_HTTP_ALLOWED_ORIGINS con origini esatte, non wildcard.
I redirect di consegna vengono rifiutati. Sul LXC si usa HTTP 127.0.0.1 diretto al proxy.
Client assenti dall'elenco non vengono cancellati; client confidenziali non vengono
sovrascritti. La CLI rimane disponibile per registrazioni/amministrazione avanzate.
Gli scope di servizio configurati vengono associati all'audience dichiarata, anche
su DB nuovo con metadata legacy. Uno scope di servizio non può appartenere a due
audience diverse: usare namespace distinti per applicazioni/risorse diverse.

## Build e avvio

```bash
npm ci
node scripts/check-config.mjs
npm run typecheck
npm run build
npm start
```

Node 24; build TypeScript più copia CSS/JS statici e dati di sicurezza. Le migration
SQL devono restare nella root `migrations/` anche per esecuzione da dist.
Avvio autonomo senza app collegate: OIDC_CLIENTS_JSON=[]; nessun servizio consumer
deve essere installato. DB e SMTP sono prerequisiti esterni, non creati dal `.env`.

### Systemd sul LXC

```bash
install -m 0644 deploy/systemd/engine-accounts.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now engine-accounts.service
./scripts/rebuild.sh
```

Checkout `/root/EngineAccounts`, porta 8080. Unit e script non avviano container né
StreamingEngine. L'infrastruttura esistente `engine-pg`/`engine-mailpit` è amministrata
separatamente (Podman restart al boot). Per utente dedicato adattare path/permessi:
il template LXC usa root. Lo script compila prima del restart; non installa dipendenze,
non fa pull, non azzera dati, non è una release atomica. Non usare su porte occupate.

### Docker Compose

`docker compose up -d --build` oppure Podman con provider Compose. Compose contiene
solo Accounts e un volume delle chiavi persistente: configurare DATABASE_URL e SMTP_HOST
raggiungibili **dal container**, non localhost dell'host. Non monta `.env` nell'immagine.
NODE_ENV è quello del `.env`; HTTPS pubblico richiede ingress esterno. DB/SMTP possono
essere gestiti da altri stack. Non eliminare il volume chiavi con `down -v`.

Sul LXC attuale manca un provider Compose e `/dev/net/tun` per la rete Podman pasta.
Il deployment supportato qui è systemd. Per build Podman si può usare `--network=host`;
questo non dimostra che la rete Compose completa funzioni in quel LXC. Non cambiare
privilegi/rete del container host per aggirare il limite senza una scelta operativa.

## Dati e backup

Migrazioni additive/idempotenti in DB_SCHEMA (default engine_accounts), protette da
advisory lock. Supporta DB separato; nessuna query su proxy_*. Preservare DATABASE_URL,
DB_SCHEMA, var/jwks.json, chiave dati esplicita o segreto da cui è derivata e cookie secret.
Non ruotare il segreto eventi senza gestire anche cifratura TOTP derivata e vecchi eventi.

`0006_default_web_client.sql` è conservata intatta per il ledger storico, ma il runner
la registra senza eseguire il vecchio seed dei domini su installazioni nuove. Nessuna
registrazione esistente viene rimossa; nuovi client arrivano da `.env`/CLI.

Backup protetto: pg_dump custom del DB, JWKS private, `.env`, unit/ingress e registrazioni
client. Restore solo su DB isolato, mai sopra produzione; verificare schema, chiavi,
login, refresh, posta, MFA e consegna eventi. Chiavi vecchie necessarie finché token
attivi: CLI keys rotate conserva la precedente. Conservare dati tra rebuild puliti.

Diagnosi: healthz/readyz, discovery issuer, /jwks, callback registrati, SMTP, journal
redatto e stato outbox. Health 200 non certifica autenticazione/browser o consegna posta.
