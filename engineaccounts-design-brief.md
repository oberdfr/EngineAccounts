# Engine Accounts — brief

Parole dell’utente: «molto più intuitiva e simile alla UI di StreamingEngine»;
«devono sembrare della stessa suite»; «glass blur/stile/animazioni»;
«tutti i dettagli dell’account devono essere visibili nella apposita schermata».

Applicazione: pannello account e amministrazione server-rendered, non catalogo
streaming o landing promozionale. StreamingEngine/DESIGN.md è riferimento canonico
in sola lettura; ereditiamo materiale, token, tipografia e comportamento.
Sostituiamo anatomia fotografica/rail con informazioni account, moduli e accessi.

Vincoli: dark-only; no blue fill; avoid broad gradients; no 3D tilt;
no heavy SVG distortion. Nessun dato o stato inventato; nessun segreto esposto.
QR TOTP locale, WebAuthn reale, sessioni non presentate come dispositivi fisici.
Percorsi critici HTML senza JavaScript, salvo WebAuthn; controlli ≥44px;
320/390/768/1440/1920px; movimento facoltativo e subordinato a reduced-motion.
