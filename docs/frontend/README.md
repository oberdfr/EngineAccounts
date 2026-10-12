# UI HTML EngineAccounts

UI same-origin del provider, non frontend SPA StreamingEngine. `src/ui/ui-routes.ts`
gestisce login, registrazione, recupero password, magic code, consenso e challenge;
`src/ui/account-routes.ts` gestisce profilo, sicurezza/MFA/passkey, sessioni, app,
attività, export e cancellazione. Inventario route in [API](../api/README.md).

Layout scuro in `src/ui/layout.ts`, CSS/JS in `src/ui/static/`, serviti da `/static/`
e copiati nel build. Non rimuovere asset non importati dal TypeScript: li usa HTML.
Token in parità con `StreamingEngine/DESIGN.md` (sola lettura): canvas #090909,
sei superfici neutre, azioni bianche, tre toni di testo, focus 2px/4px e bersagli
44px. Geist Variable e Inter Variable da fontsource sono copiati dal build in
`dist/ui/static/fonts/`; nessun font/CSS remoto o codice consumer importato.
Il linguaggio adattato all’identità è documentato in `DESIGN.md`: stesso vetro
nero 52–60%, blur 20–24px, bordo bianco 9%, senza fotografie dimostrative,
gradienti decorativi o import dal frontend consumer. Intestazione, sidebar,
profilo, sicurezza e amministrazione condividono primitive e gerarchia.
Gli asset usano una revisione nell’URL per evitare il riuso del vecchio CSS.
Le animazioni sono disattivate per default; il controllo nel footer salva una
preferenza solo su questo browser e rispetta sempre il movimento ridotto.

La scelta Account/Admin vive nei link dell’header, con la pillola glass della
voce attiva come la navigazione Home/Film/Serie di StreamingEngine: non è un
dropdown. I veri campi select usano `select-controls.css`/`select-controls.js`
in tutto il sito, inclusi filtri account e impostazioni Admin: trigger, popup,
segno di selezione e chevron a 16px dal bordo, testo con padding finale 48px.
Il select nativo resta il controllo del form e il fallback senza JavaScript.
La navigazione Account non contiene collegamenti
amministrativi e il Profilo non ospita pannelli di amministrazione dei servizi.
Per gli amministratori assegnati il link Admin usa soltanto destinazioni
autorizzate lato server; non rimanda alla root globale `/admin`.
La card “Gestisci Engine” nella panoramica globale resta una scorciatoia
esplicitamente richiesta, non una seconda navigazione amministrativa.
TOTP attivo mostra lo stato e raccoglie la disattivazione in un gruppo nativo
espandibile con un form spaziato. Export separa l’azione di download dal testo;
il badge di verifica email accompagna il nome nella panoramica.
Navigazione laterale account/admin desktop, menu nativo compatto su mobile;
tabelle in regioni `.table-scroll` etichettate. Le conferme admin restano form
nativi con conferma esplicita anche senza JavaScript. La conferma progressiva
di cancellazione usa `dialog.showModal()`, focus confinato, Escape e ritorno focus.
Form POST con CSRF, stati pending/errore, label/focus e validazione server. Username,
password, codici e sessioni restano qui, non nei consumer.

Consenso mostra applicazione, scope e risorsa registrati; callback/logout derivano
da dati client esatti. Le pagine OIDC conservano cookie/interazione del provider.
Logout esegue il POST originale con xsrf e submitter, conferma senza JavaScript;
auto-submit solo con prove di legame token/client/sessione. Nessun bypass via query.

Verificare tastiera, touch, zoom, layout mobile e CSP su browser reali. Cambiare il
dominio richiede impostare issuer/public base e ingress, non modificare template UI.

Admin Engine solo globali; pannelli di servizio solo globali/assegnati, ruolo
verificato per richiesta lato server. Le card SSO collegano `adminUrl`; gli
settings consumer non sono renderizzati. Lo stato outbox è distinto dall'health
del consumer. Ri-verifica valida cinque minuti, TOTP/passkey sempre richiesta.

## Account e accessi

- `/` riconosce la sessione e rimanda direttamente a `/account`; risposte
  personalizzate `no-store`. Il visitatore anonimo vede accesso/registrazione.
- Profilo: identificatore, nome, email/verifica, stato, date, ruolo Engine,
  amministrazione servizi, TOTP, policy password e blocco temporaneo. Hash,
  token e segreti non sono dettagli da esporre.
- Sessioni: credenziali di accesso, **non dispositivi**. I gruppi browser/OS
  sono solo indicazioni, non fingerprint affidabili. Accessi attivi e cronologia
  revocata/scaduta sono distinti; la cronologia non aumenta gli accessi attivi.
  Revoca singola o di tutte le altre sessioni; quest’ultima conserva il login
  corrente e il suo eventuale collegamento OIDC condiviso.
- Login standalone ripetuto sul medesimo account riusa la sessione soltanto
  con gli stessi metodi di autenticazione. Le interazioni OIDC mantengono il
  collegamento provider proprio: non sono fuse sulla base dello user-agent.
- TOTP: QR SVG generato localmente, alternativa manuale, conferma del codice,
  segreto pending stabile dopo un errore. Un fattore confermato non viene
  sovrascritto visitando nuovamente la pagina di configurazione.
- Passkey: opzioni JSON realmente consegnate al client, credenziale
  discoverable con verifica utente, registrazione legata alla sessione,
  nome facoltativo, login `/ui/passkey`, errore/annullamento e retry espliciti.
  JavaScript è necessario per WebAuthn; TOTP conserva il percorso HTML.
