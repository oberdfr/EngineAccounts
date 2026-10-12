---
name: "engineaccounts-suite-design"
description: "Pannello identità Engine su canvas nero, Geist e Inter locali, azioni bianche e vetro neutro 52–60% con blur 24px. Informazioni account ordinate, controlli nativi e movimento facoltativo."
colors:
  primary: "#f5f5f5"
  on-primary: "#141414"
  primary-hover: "#dedede"
  canvas: "#090909"
  surface-1: "#121212"
  surface-2: "#191919"
  surface-3: "#202020"
  surface-4: "#282828"
  surface-5: "#303030"
  surface-6: "#383838"
  ink: "#f5f5f5"
  body: "#d0d0d0"
  ink-muted: "#b0b0b0"
  hairline: "#343434"
  hairline-soft: "#242424"
  hairline-strong: "#777777"
  signal: "#e0e0e0"
  signal-hover: "#ffffff"
  signal-surface: "#292929"
  success: "#84dbc1"
  success-surface: "#142b27"
  warning: "#f1ca82"
  warning-surface: "#302819"
  danger: "#ffb0b0"
  danger-surface: "#331d25"
  danger-border: "#744c56"
  scrim: "#080808"
typography:
  display:
    fontFamily: "Geist Variable, Geist, system-ui, sans-serif"
    fontSize: "clamp(32px, 24px + 2vw, 48px)"
    fontWeight: "600"
    lineHeight: "1.12"
    letterSpacing: "-0.03em"
  body:
    fontFamily: "Inter Variable, Inter, system-ui, sans-serif"
    fontSize: "16px"
    fontWeight: "400"
    lineHeight: "1.55"
    letterSpacing: "0em"
---

## Overview

Adattamento del sistema canonico [StreamingEngine](../StreamingEngine/DESIGN.md),
letto anche in `styles/tokens.css` e `account/account.css` del servizio web.
Nessun codice consumer importato o modificato. Firma: **vetro nero neutro locale**,
con bordo luminoso discreto, gerarchia editoriale e navigazione ordinata.

Ereditiamo colori, font, focus, raggi, materiali e policy del movimento;
sostituiamo fotografia, rail e player con moduli, fatti account e sessioni.
Non inventiamo immagini per rendere visibile il blur. Fonte eseguibile:
`src/ui/layout.ts`, `pages.ts`, `admin-routes.ts`, `static/app.css`.
I controlli dell’header sono definiti in `static/header-controls.css` e
`static/header-controls.js`, senza import dal consumer.

## Colors

### Brand & Accent
Bianco primary/on-primary per una sola azione dominante per gruppo. Signal per
focus e selezione; mai un secondo accento decorativo.

### Surface
Canvas e sei superfici identiche al riferimento. Superfici più chiare per
controlli ed elevazione, non alternanza di fasce. Fallback opachi dove manca
backdrop-filter; regole glass dopo i fallback nella cascata CSS.

### Text
Ink per titoli e valori, body per lettura, ink-muted per suggerimenti.
Mai abbassare l’opacità del testo. UUID/email/codici vanno a capo.

### Semantic
Success/warning/danger solo con etichetta esplicita. Non usare il colore come
unico indicatore e non trasformare avvisi in decorazione della pagina.

## Typography

### Font Family
Geist Variable 600 per titoli e marchio; Inter Variable 400–600 per corpo,
navigazione, campi e pulsanti. Fontsource locali, distribuiti con licenze.

### Hierarchy
H1 32–48px/1.12; H2 24–32px/1.2, nei pannelli 22px/1.3; corpo 16px/1.55;
etichette e metadati 14px; eyebrow 12px/600 con tracking 0.14em.

### Principles
Un H1, sezioni H2, fatti in dl/dt/dd, date reali con fuso esplicito.
Numeri tabulari per conteggi. Dashboard sintetica; dettagli nel Profilo.

### Note on Font Substitutes
System-ui è riserva durante il caricamento, non font distribuito al posto
di Geist/Inter. Verificare HTTP200 e `document.fonts` nel browser.

## Layout

### Spacing System
Unità 4px, ritmo 8px; scala 4/8/12/16/20/24/32/40/48/56/64/80px.
Pannelli 24px desktop, 16px mobile; azioni 12px; campi 8px.

### Grid & Container
Sidebar 224px, contenuto minmax(0,1fr), gap24–48px. Contenitore account
1760px, 2080px da1760px; lettura sempre entro68ch. Dashboard auto-fit300px;
identità e permessi non allargano la pagina. Navigazione mobile sotto1200px.

### Whitespace Philosophy
Sezioni raggruppate per compito. Una panoramica, tre schede actionable e pannelli
amministrativi autorizzati; non ripetere tutti i dettagli del profilo nella home.

## Elevation & Depth
Glass fill rgb(12 12 12 /52%), raised60%, edge bianco9%, blur24px.
Header sticky z30, menu40, dialogo nel top layer; nessun z-index9999.
Ombra pannello nera22%, flottante36%, modale56%. Focus2px offset4px,
campi3px. Animazioni off per default, opt-in locale, stati300ms e comparsa280ms
con massimo4px. Reduced-motion elimina sempre il movimento non essenziale.

## Shapes
Raggi6px indicatori,10px campi,16px pannelli,24px dialoghi/auth desktop,
pulsanti pill999px. Bersagli44px, nessun controllo rimpicciolito su telefoni.

## Components
- Header glass: marchio suite, link Account/Admin autorizzati e identità/logout.
  La voce attiva usa la pillola glass della navigazione StreamingEngine;
  Account/Admin non è un dropdown e non richiede JavaScript.
- Select in tutto il sito: trigger/popover della suite, segno di selezione,
  chevron 18px a 16px dal bordo e padding finale 48px. Il controllo nativo
  conserva valore, invio form e fallback senza JavaScript. Enhancement locale
  in `select-controls.css`/`select-controls.js`, senza import dal consumer.
- Sidebar/menu nativo: stessa mappa di funzioni, aria-current per pagina.
  L’area Account non inserisce l’amministrazione nella sidebar o nel Profilo.
- Panel/card: intestazione, dati, aiuto, azione esplicita. Un pannello statico
  non diventa cliccabile solo tramite hover.
- Field: label associata, hint/error descritti, required e aria-invalid.
- Sessioni: accessi correnti e storici; gruppi browser indicativi, mai fingerprint
  presentato come identità di un dispositivo. Espansione nativa dei dettagli.
- TOTP: QR locale responsive, chiave manuale e conferma; niente servizi esterni.
- WebAuthn: solo operazioni native reali, opzioni JSON sicure, errori e retry.
- Dialogo nativo: showModal, Escape, focus confinato e ritorno focus; conferma
  HTML esplicita delle azioni sensibili anche senza JavaScript.
- Tabelle: caption, intestazioni e regione di scroll etichettata/tabulabile.
- Stati vuoti/errori: spiegare motivo, conseguenze e prossimo passo; niente
  redirect admin senza una spiegazione di MFA o ri-verifica.

## Do's and Don'ts
- no blue fill
- avoid broad gradients
- no 3D tilt
- no heavy SVG distortion
- Dark-only, controlli ≥44px, dato mancante etichettato come mancante.
- Mai esporre password/hash/token/digest o chiavi per “completare” il Profilo.
- Mai chiamare “dispositivi” un conteggio di sessioni o inventare geolocalizzazione.
- Niente JS indispensabile ai flussi critici HTML; WebAuthn è eccezione esplicita.

## Responsive Behavior
Verifiche320/390/768/1440/1920px, font reali, tastiera, JS/no-JS e reduced-motion.
Mobile: menu completo, pannelli16px, azioni a capo, QR max-width100%.
Tabelle scorrono localmente; conteggi sessioni restano compatti. Testi ingranditi
e dati lunghi non devono produrre overflow o tagliare errori.

## Iteration Guide
1. Conservare token identici al riferimento e specificare adattamenti account.
2. Riutilizzare primitive interne senza importare consumer.
3. Testare dati veri o fixture dichiarate, mai stati API inventati.
4. Controllare valori glass computati: una regola CSS presente può essere sovrascritta.
5. Eseguire gate e verifiche browser; documentare limiti effettivi.

## Known Gaps
Zoom nativo, Safari/iOS, QR scanner e passkey fisiche non certificati dalle prove
Chromium sintetiche. Il movimento locale non modifica preferenze dei consumer.
La suite visiva non implica che inviti o health consumer opzionale siano
implementati. Esiti: `docs/testing/account-ui-redesign-results.md`.
