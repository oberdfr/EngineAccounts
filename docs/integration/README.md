# Consumer indipendenti

EngineAccounts non importa sorgenti, dati o unit dei consumer. Registrare client
pubblici tramite OIDC_CLIENTS_JSON nel `.env`, client confidenziali tramite CLI.
OIDC_CLIENTS_JSON=[] avvia il provider senza alcuna applicazione collegata.

Per [StreamingEngine](https://git.oberdfr.top/oberdfr/StreamingEngine) dichiarare
clientId coerente con OIDC_CLIENT_ID, redirect `/auth/callback` e logout `/` sull'origine
PUBLIC_APP_URL del consumer, audience coerente con OIDC_AUDIENCE, scope openid/profile/
email/offline_access e streaming:catalog/playback/account. backchannelEventsUri punta
all'endpoint interno del proxy, non alla SPA. Esempio completo in `.env.example`.

Stesso OIDC_ISSUER pubblico e OIDC_EVENT_SIGNING_SECRET nei due `.env`, ma cookie key,
data key/JWKS Accounts e encryption key SC StreamingEngine sono separati. OIDC_JWKS_URL
del proxy può usare un collegamento interno senza cambiare issuer. Host/db possono
essere diversi: il collegamento è OIDC/JWKS + eventi HTTP, non un filesystem condiviso.

DNS/TLS/ingress e SMTP/database sono prerequisiti reali: il file `.env` non li crea.
Rebuild/restart Accounts non riavvia StreamingEngine e viceversa. Provider indipendente
non significa login possibile quando esso è spento: il consumer può offrire soltanto
feature anonime e token già verificabili entro scadenza.
