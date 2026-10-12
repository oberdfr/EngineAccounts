# EngineAccounts

Provider OIDC autonomo e UI di gestione identità: account, sessioni, client,
consensi, MFA/passkey, posta, token e CLI. Non richiede il checkout o l'avvio di
StreamingEngine; può servire più applicazioni tramite registrazioni configurate.

## Installazione

Prerequisiti: Node **24**, PostgreSQL raggiungibile, SMTP per tutte le funzionalità
email, DNS/TLS/ingress per esposizione pubblica. Tutta la configurazione applicativa
è in **un solo `.env` alla radice**; vedere `.env.example`.

```bash
cp .env.example .env   # nuovo ambiente: compilare DB, domini, segreti, SMTP e client
npm ci
node scripts/check-config.mjs
npm run build
npm start
```

Il servizio migra il proprio schema, registra i client pubblici di OIDC_CLIENTS_JSON
e genera JWKS solo se manca. Per avvio autonomo senza consumer impostare `[]`.
Non sostituire i segreti o le chiavi di un ambiente esistente.

## Documentazione

- [API OIDC, funzionalità, UI e CLI](docs/api/README.md)
- [Contratto OIDC/eventi](contracts/oidc.md)
- [Configurazione, installazione, systemd, Docker e backup](docs/operations/README.md)
- [Sicurezza e persistenza](docs/security/README.md)
- [Test e fixture browser](docs/testing/README.md)
- [Interfaccia HTML](docs/frontend/README.md)
- [Integrazione con StreamingEngine](docs/integration/README.md)

Sul LXC: `/root/EngineAccounts`, unit `engine-accounts.service`, porta `8080`.
StreamingEngine resta in `/root/StreamingEngine`, con un'altra unit e un altro `.env`.
Build/restart indipendente: `./scripts/rebuild.sh`. Non reinstallare infrastruttura
o azzerare database per un aggiornamento del servizio.
