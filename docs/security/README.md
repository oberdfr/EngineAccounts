# Sicurezza EngineAccounts

Authorization Code + PKCE S256, JWT EdDSA/RS256, redirect esatti, refresh rotante con
reuse detection. Nessun password grant o secret nel client pubblico. Client secret
e password sono hash Argon2id, MFA cifrato con data key separata/HKDF. Rate limit,
risposte neutrali, reset/verifica monouso e CSRF proteggono form e pannello.

Cookie host-only, Secure su HTTPS, HttpOnly, SameSite=Lax. Non attivare automaticamente
__Host-: il cookie resume usa Path=/auth/<uid>. TRUST_PROXY soltanto con ingress fidato;
proteggere la porta diretta e configurare TLS/HSTS. CSP deriva origini dei client;
logout conserva POST/xsrf del provider. Token/cookie/password non vanno nei log.

`.env`, JWKS private e backup sono segreti: permessi restrittivi, mai nel repository
o nelle immagini. Persistenza chiavi obbligatoria tra deploy. Non cambiare derivazione
dei segreti con dati cifrati esistenti. Nessun accesso ai dati applicativi dei consumer.

Eventi account.deleted: JWS HS256 sul JSON canonico con HKDF, audience del client,
issuer e scadenza, jti per replay. Solo URL registrati; Origin è un controllo secondario,
non autenticazione. Il consumer deve riservare l'endpoint via ingress/firewall.
204/409 sono consegna completata, errori vanno nell'outbox; JWT già emessi possono
restare validi nei consumer offline fino a exp. Nessuna promessa di revoca istantanea.

Vedere [contratto](../../contracts/oidc.md) e [test](../testing/README.md).
Questa guida non è una certificazione ASVS. TLS, browser, restore, email e MFA richiedono prove
specifiche; servizi esterni o host compromessi restano rischi non risolti da test verdi.
