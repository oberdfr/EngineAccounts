# UI HTML EngineAccounts

UI same-origin del provider, non frontend SPA StreamingEngine. `src/ui/ui-routes.ts`
gestisce login, registrazione, recupero password, magic code, consenso e challenge;
`src/ui/account-routes.ts` gestisce profilo, sicurezza/MFA/passkey, sessioni, app,
attività, export e cancellazione. Inventario route in [API](../api/README.md).

Layout scuro in `src/ui/layout.ts`, CSS/JS in `src/ui/static/`, serviti da `/static/`
e copiati nel build. Non rimuovere asset non importati dal TypeScript: li usa HTML.
Form POST con CSRF, stati pending/errore, label/focus e validazione server. Username,
password, codici e sessioni restano qui, non nei consumer.

Consenso mostra applicazione, scope e risorsa registrati; callback/logout derivano
da dati client esatti. Le pagine OIDC conservano cookie/interazione del provider.
Logout esegue il POST originale con xsrf e submitter, conferma senza JavaScript;
auto-submit solo con prove di legame token/client/sessione. Nessun bypass via query.

Verificare tastiera, touch, zoom, layout mobile e CSP su browser reali. Cambiare il
dominio richiede impostare issuer/public base e ingress, non modificare template UI.
