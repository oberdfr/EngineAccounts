# Seconda revisione UI/UX account — 12 ottobre 2026

## Cambiamenti di prodotto

- Nuova struttura condivisa account/admin: header glass, identità, navigazione
  laterale desktop, menu nativo mobile, pagina corrente e percorso.
- Materiale canonico Engine: nero 52–60%, blur 24px, bordo bianco 9%, Geist e
  Inter locali. Verificati i valori **computati**, non solo la presenza dei token.
- Animazioni facoltative, off per default, preferenza locale; movimento ridotto
  sempre prioritario. URL asset revisionati per evitare vecchie cache CSS.
- Dashboard autenticata direttamente dalla home; profilo completo senza segreti.
- Sicurezza con TOTP QR locale, chiave manuale, conferma, passkey, recupero e
  messaggi di errore. Il QR non passa da servizi esterni.
- Passkey: opzioni JSON incluse nella pagina, challenge legata alla sessione,
  verifiche origin/RP/utente/counter, credenziale discoverable, nome facoltativo,
  login dedicato, annullamento/retry. Nessun successo finto per challenge scaduta.
- Sessioni distinte dai dispositivi: gruppi indicativi browser/OS, accesso
  corrente, date/scadenza/IP/metodi, storico scaduto/revocato e revoche reali.
  La cronologia non aumenta il conteggio attivo. Login standalone identici non
  moltiplicano inutilmente le sessioni; OIDC mantiene i propri legami.
- Pannelli globali e assegnati, account/dettagli/ruoli, servizi, impostazioni,
  audit, diagnostica/outbox: istruzioni di ambito e conseguenze delle azioni.
  L’admin richiede un fattore configurato **e verificato nella sessione**;
  password-only riceve una pagina esplicativa, mai accesso privilegiato.

## Prove

- Typecheck, build e check-config passati.
- `npm test`: 223 test, 26 file, tutti passati, nessun salto.
- Chromium: matrice di 28 schermate × 5 larghezze × JS/no-JS = 280 viste.
  Font locali, un H1, controlli selezionati ≥44px, tastiera, tabelle etichettate,
  movimento ridotto, menu e assenza di overflow. Il QR a 320px è stato corretto
  e i due casi falliti sono stati rieseguiti con successo.
- Dialoghi nativi: confinamento/ritorno focus, sfondo inerte, Annulla/Escape
  senza POST, Conferma con un solo POST **sintetico**.
- Chromium virtual authenticator: registrazione, cancel/retry e autenticazione
  discoverable reali. Risposte pubbliche catturate verificate crittograficamente
  dal servizio MFA; challenge/account/origin/RP errati e replay rifiutati.
- Integration: QR e chiave pending stabile, home autenticata, opzioni WebAuthn,
  rifiuto challenge cross-session, messaggi di errore e isolamento delle revoche.

Solo harness `engine_accounts_test`, chiavi sintetiche e fixture loopback.
Nessun deploy/restart, revoca di sessioni reali o modifica ai consumer.

## Limiti e verifiche operatore

- L’autenticatore virtuale non certifica Face ID, Windows Hello, Android/iOS,
  scanner QR fisici o l’intero percorso browser→DB sui dispositivi dell’utente.
  Verificare quelli dopo il rilascio senza condividere password o segreti TOTP.
- Reflow equivalente non è certificazione dello zoom nativo del browser.
- Browser sintetico non equivale a SMTP o API consumer produttive verificate.
- Modalità inviti resta chiusa alla registrazione libera; creazione/consumo
  inviti e health consumer opzionale non sono implementati. Nessuna UI li
  presenta come funzionalità operative.
- Audit dipendenze rileva finding high preesistenti relativi a
  `@fastify/static`/`nodemailer`: richiedono un aggiornamento separato e testato.
- Password, token, digest sessione e chiavi non sono dati da mostrare nella UI.

Per pubblicare seguire `docs/operations/README.md` e `./scripts/rebuild.sh`.
Il solo `systemctl start` non sostituisce un processo già attivo.

## Ritocchi successivi — Account/header

Selettore Account/Admin e menu identità aggiornati osservando le primitive
StreamingEngine `ui/select.css`/`select.tsx`, senza import dal consumer.
Scelte di navigazione native senza JS; progressive enhancement con tastiera,
Escape, click esterno e ritorno focus. L’area selezionata deriva dalla route.
Destinazioni degli admin assegnati derivate dalle autorizzazioni lato server.

Account non mostra Amministrazione nella sidebar o nel Profilo. La card globale
“Gestisci Engine” resta con il testo richiesto; il riepilogo sessioni non contiene
più la spiegazione sui dispositivi (che resta nella schermata Sessioni).
Badge email accanto al nome, TOTP compatto con disattivazione espandibile e form
spaziato, margine download export 32px. Nessuna revisione dei contenuti Admin.

Gate successivi: **236 test, 27 file**, typecheck, build e check-config passati.
Audit browser mirato: **120/120 casi**, zero errori browser, cinque larghezze,
JS/no-JS e ruoli globale/ordinario/assegnato. Verificati selettore e navigazione
effettiva da tastiera, Escape/click esterno/ritorno focus, menu profilo, badge
laterale desktop, form TOTP, margine export esatto 32px e movimento ridotto.
Prove su fixture sintetiche; nessuna modifica ai dati o ai servizi produttivi.

## Correzione navigazione e dropdown globali

La richiesta successiva chiarisce che Account/Admin non deve essere un menu:
sono link permanenti con pillola glass sulla voce attiva, come Home/Film/Serie
di StreamingEngine. Questa implementazione sostituisce il selettore header
descritto nella sezione precedente. La navigazione resta interamente nativa.

Tutti i veri campi select (filtri Account Engine e impostazioni Admin inclusi)
usano ora lo stesso materiale e comportamento dropdown della suite:
`select-controls.css`/`select-controls.js`, asset revisionati `ui4`.
Chevron 18px a 16px dal bordo; padding finale 48px anche senza JavaScript.
Il controllo nativo mantiene nome, valore, validazione e invio form.

Gate: **244 test, 28 file**, typecheck, build, check-config e diff-check passati.
Regressioni aggiunte per target ARIA presente da subito e rimozione/spostamento
dinamico dei select senza reinserire campi eliminati nei form.
L’audit browser ha inoltre rilevato una sincronizzazione anticipata del reset:
il display custom veniva aggiornato prima dell’azione predefinita del form.
Il reset viene ora sincronizzato nel task successivo, non in una microtask;
le regressioni coprono sia il reset nativo sia il reset annullato.
Verifica browser finale: **30/30 casi select passati**, cinque larghezze con
JS/no-JS, zero errori browser/CSP. Reset display, reset required/invalid e reset
annullato verificati insieme a tastiera, query form, label, optgroup/disabled,
posizionamento popup e rimozione/spostamento dinamico. I **120 casi Account**
erano già passati nella verifica precedente e non sono stati rieseguiti dopo
la sola correzione reset. Fixture e tunnel temporanei arrestati.
