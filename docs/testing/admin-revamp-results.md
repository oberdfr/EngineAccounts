# Verifiche revamp Accounts — 12 ottobre 2026

## Gate eseguiti

| Verifica | Esito |
| --- | --- |
| `npm run typecheck` | Passato |
| `npm test` | 191 test passati, 21 file, nessun salto |
| `npm run build` | Passato; font e licenze copiati localmente |
| `node scripts/check-config.mjs` | Passato; nessun valore/segreto stampato |
| Chromium UI isolata | 25/25 pagina/viewport |
| Reflow equivalente 200% | 15/15 |
| Dialogo nativo prodotto | 3/3: Annulla, Escape, Conferma |

Test DB soltanto in `engine_accounts_test`, JWKS di test, porte loopback
effimere. La CLI viene esercitata dalla harness su schema test, non sullo stack
pubblico. Migrazioni `0008`/`0009` applicate soltanto nello schema di test.

Le prove browser usano fixture sintetiche senza DB o sessioni reali, viewport
320/390/768/1440/1920px, JavaScript disabilitato per i flussi HTML e font locali.
Il test del dialogo usa JavaScript e la pagina prodotto, sostituendo soltanto
l'action POST con un handler sintetico: focus confinato, sfondo inerte,
ritorno focus, zero invii per Annulla/Escape e un solo invio su Conferma.
Nessun overflow osservato; un H1 e bersagli selezionati di almeno 44px.

## Limiti espliciti

- Zoom **nativo** 200% non verificato: è verificato il reflow equivalente.
- Safari/iOS, passkey hardware, delivery SMTP produttiva e interoperabilità
  con API admin consumer reale non verificate. Le prove Chromium non le certificano.
- Il lato consumer resta fuori scope; formato esatto in
  [consumer-admin.md](../integration/consumer-admin.md).
- Modalità registrazione `invite` impedisce nuove registrazioni libere, ma
  generazione e consumo di inviti non sono implementati. Non presentarla come
  un flusso inviti operativo.
- Stato salute consumer opzionale non implementato; outbox e abilitazione non
  dimostrano che il servizio sia sano.
- Nessuna certificazione ASVS, nessun deploy o restart produttivo.
- `.env`, `var/jwks.json`, migrazioni storiche e StreamingEngine non modificati.

Procedura operatore: [operazioni](../operations/README.md), sezione aggiornamento
1.1.0. Il nuovo bootstrap globale è esclusivamente CLI su un sub esistente.
