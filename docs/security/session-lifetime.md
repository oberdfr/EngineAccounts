# Sessione permanente (AUTH-AUDIT fix A, C, D)

Obiettivo di prodotto: **l'accesso dura finché non si fa logout esplicito**. Questa
pagina documenta i valori e i meccanismi che lo rendono vero; il dettaglio del
difetto originale è nell'audit esterno `streamingengine-tv/docs/AUTH-AUDIT.md`.

## Valori

| Artefatto | Valore | Dove |
|---|---|---|
| Access token | **900 s (15 min)** | `.env ACCESS_TOKEN_TTL`, `src/config.ts` |
| ID token | **900 s (15 min)** | `.env ID_TOKEN_TTL` |
| Refresh token | **7 776 000 s (90 giorni), scorrevole** | `.env REFRESH_TOKEN_TTL` |
| Sessione IdP (`Session`) e `Grant` | **7 776 000 s (90 giorni), scorrevoli** | `.env SESSION_TTL`, `src/config.ts` |
| Sessione locale (`sessions`, cookie `ea_sid`) | scorrevole, tetto `SESSION_TTL` | `src/services/session-manager.ts` |
| Cookie di sessione IdP (`ea_oidc`) | `HttpOnly; Secure; SameSite=Lax; Path=/`, rinnovato a ogni uso | `src/oidc/provider.ts` |
| Authorization code | 60 s | `src/oidc/provider.ts` |

Il vincolo reale del refresh è `min(RefreshToken, Grant, Session)`: per questo i tre
valori sono allineati a 90 giorni. Prima `SESSION_TTL` era 14 giorni e la sessione non
scorreva: il refresh token da 30 giorni moriva comunque al 14° giorno dal login.

## Scorrimento

- **Refresh token**: a ogni rotazione il successore ha `exp = now + REFRESH_TOKEN_TTL`
  (comportamento della libreria, ora con 90 giorni come base).
- **Sessione IdP e grant**: `slideSessionExpiry` (`src/oidc/adapter.ts`) riporta `exp`
  avanti a ogni scrittura del modello `Session`; l'adapter allinea `expires_at` in
  tabella. Mai all'indietro, mai oltre `now + SESSION_TTL`.
- **Sessione locale**: `SessionManager.resolve` sposta `expires_at` avanti a ogni uso allo
  stesso tetto (`touchSession(id, expiresAt)`).

## Logout esplicito

`/end-session` (logout RP-initiated), `/revoke`, la revoca per dispositivo e
"revoca altre sessioni" continuano a distruggere sessione, grant e token: lo
scorrimento è **solo per l'uso**, non contro la revoca. Un utente disattivato o
con cambio password forzato perde l'accesso al primo rinnovo.

## Frame del silent renew (fix A)

`GET /auth?prompt=none` è la **sola** risposta incorniciabile: `frame-ancestors`
elenca le origini dei `redirect_uri` dei client registrati e **non** emette
`X-Frame-Options` (un `DENY` annullerebbe la direttiva). Pagine di login, consenso,
account, admin e ogni altra rotta OIDC restano `frame-ancestors 'none'` +
`X-Frame-Options: DENY`. Il calcolo è in `src/security/headers.ts`
(`isSilentAuthorizationRequest`, `frameAncestorsSources`), il montaggio in
`src/app.ts`.

Nota: i cookie sono `SameSite=Lax`, quindi il silent renew in iframe cross-site
funziona solo dove il browser invia il cookie (Chrome/Firefox con cookie di terze
parti abilitati). Safari e i browser con partizionamento dei cookie possono
richiedere un nuovo login: è un limite di piattaforma, la vera soluzione stabile
è il refresh token persistito lato client (fix B dell'audit, lato web).

## Rotazione con grace window (fix C)

`rotateRefreshToken: true` consuma il refresh token a ogni uso. Il **riuso entro
30 s** (`REFRESH_TOKEN_GRACE_SECONDS`) è **idempotente**: stesso refresh token
successore in risposta e nuovo access token dello stesso grant, nessuna revoca.
Oltre i 30 s la reuse detection resta attiva e revoca l'intera famiglia.
Il meccanismo vive nell'handler del grant (`wrapRefreshTokenGrant`,
`src/oidc/adapter.ts`), che ripresenta alla libreria il successore già emesso;
`consume()` nello store è atomico (`UPDATE ... WHERE consumed_at IS NULL`).

## Variabili escluse dal versionamento

`.env` è segreto. Questo documento riporta solo i **nomi** e i valori dei TTL.
