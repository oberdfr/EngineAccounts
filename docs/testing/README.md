# Test EngineAccounts

```bash
npm run typecheck
npm test
npm run build
```

Integration/security usa schema dedicato **engine_accounts_test** e var/jwks-test.json.
La harness svuota tabelle di test e rifiuta cleanup su schema senza suffisso `_test`.
Non impostare DATABASE_URL o DB_SCHEMA di test sui dati produttivi; per nuove prove
end-to-end usare un database separato e chiavi temporanee. Unit non richiede consumer.

`tests/unit/default-web-clients.test.ts` verifica client dichiarativi, assenza consumer,
URI/JSON invalido, scope e registrazione parametrizzata. `env-root.test.ts` verifica
caricamento `.env` da src/dist senza configurazione nel parent. Suite OIDC verifica
code/PKCE, claim, refresh/reuse, client confidenziali e cookie.

## Browser isolato

`node node_modules/tsx/dist/cli.mjs tests/browser/logout-fixture.ts` e poi
`tests/browser/logout.browser.js` con runner Playwright. Fixture loopback 18080/15173,
sessioni/chiavi sintetiche senza DB reale; si arresta dopo due minuti. Provare POST
CSRF unico, fine sessione, redirect esatto, rifiuto redirect arbitrario e CSP.

`node scripts/http-e2e.mjs http://127.0.0.1:<porta-test>` registra un client/account
di test: **solo ambiente isolato**, con SMTP/Mailpit dedicato. Verifica discovery,
registrazione, verifica mail, login, consenso, code/token, userinfo, refresh/reuse.
Non usarlo come lettura innocua sullo stack pubblico. Output token opzionale va in
file protetto fuori repo; non pubblicare log con code, secret, cookie o link verifica.

Per integrazione con StreamingEngine provare token reale tramite JWKS e evento
firmato da questo emitter contro proxy isolato. Health, HTTP, browser e video sono
prove diverse; skip/dipendenze mancanti non vanno dichiarati passati.
