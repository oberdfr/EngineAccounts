# Client nativi Android / WebView

Un client nativo è pubblico, usa Authorization Code con PKCE S256 e può avere
refresh token ruotati. `application_type` è un dato esplicito, non è dedotto
dal nome del client o dallo scheme del redirect. Le registrazioni esistenti
restano `web` grazie al default della migrazione additiva `0010_native_clients.sql`.
Nessun account, consenso, grant, sessione o signing key viene ricreato.

Esempio StreamingEngine Android:

```bash
npm run cli -- client add streamingengine-android --type public \
  --application-type native --cors-origin https://localhost \
  --redirect-uri streamingengine://auth/callback \
  --post-logout-uri streamingengine:// \
  --scope openid,profile,email,offline_access,streaming:catalog,streaming:playback,streaming:account \
  --audience https://api.engine.local/streaming \
  --name 'StreamingEngine Android'
```

La CLI aggiorna per ID: verificare la registrazione esistente prima di usarla.
Per StreamingEngine mantenere anche lo stesso backchannel account-deleted del
client web, se configurato. Non aggiungere client secret al bundle.

## Confini di sicurezza

- `application_type=web` resta il default; le origini aggiuntive sono riservate
  ai client nativi pubblici. Valori non validi sono rifiutati dal repository,
  dalla CLI e quando il provider carica il metadata.
- `cors_origins`: massimo otto origini HTTPS canoniche esatte. Vietati wildcard,
  `null`, credenziali URL, path/fragment e HTTP. L'origine Android
  `https://localhost` è distinta dal redirect `streamingengine://...`.
- Il CORS del token/revocation endpoint è legato al client della richiesta.
  Abilitare Android non abilita `https://localhost` sui client web esistenti.
- Gli scheme applicativi non entrano nella allowlist delle origini CORS.
  `originOf` rifiuta origini opache: la stringa `null` non diventa autorizzata.
- La CSP delle sole interazioni ammette gli scheme dei client nativi registrati;
  logout aggiunge solo la destinazione già validata dal provider. State/nonce,
  PKCE, redirect esatto e issuer/audience restano verificati normalmente.
- Lo scheme privato può essere registrato anche da un'altra app: PKCE protegge
  il code. Una futura migrazione a verified HTTPS App Links richiede dominio,
  assetlinks, firma e configurazione Android coerenti, non redirect fittizi.

La policy iniziale riguarda Android HTTPS WebView. iOS richiede una policy e
prove dedicate per l'origine `capacitor://localhost`, non una wildcard generale.
I test backend usano esclusivamente lo schema isolato `engine_accounts_test`.
