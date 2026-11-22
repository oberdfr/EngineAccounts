-- 0011_oidc_rotation.sql -- grace window e sessione scorrevole.
--
-- `oidc_tokens` guadagna una colonna di servizio (`rotation`, JSONB) per i dati
-- di rotazione che **non** devono stare nel payload del modello: la libreria
-- rilegge quel payload e un campo in piu' e' un rischio inutile.
--
--   rotation.consumedAtMs : quando il token e' stato consumato, in millisecondi.
--                           Base della grace window (30 s) sul riuso del
--                           refresh token: entro la finestra la risposta e'
--                           idempotente, oltre scatta la reuse detection.
--   rotation.successor    : il jti del successore emesso per questo token,
--                           scritto alla rotazione (`SetSuccessor`). E' un
--                           puntatore, non un segreto: serve a ripresentare
--                           alla libreria lo stesso successore.
--
-- Nessun dato preesistente viene riscritto: i token gia' emessi non hanno
-- `rotation` (NULL) e il codice tratta NULL come "nessuna rotazione nota".
-- Il payload JSON non cambia: `consumed` continua a stare dove la libreria lo
-- cerca, e `consumed_at` (colonna) resta l'evidenza di audit.
ALTER TABLE oidc_tokens
  ADD COLUMN IF NOT EXISTS rotation jsonb NOT NULL DEFAULT '{}'::jsonb;

-- La grace interroga i token consumuti di recente per `id`: l'indice primario
-- basta. L'indice parziale rende veloce "chi e' stato consumato poco fa" nei
-- controlli operativi e nella manutenzione, senza pesare sulle scritture.
CREATE INDEX IF NOT EXISTS oidc_tokens_rotation_consumed_idx
  ON oidc_tokens ((rotation ->> 'consumedAtMs'))
  WHERE rotation ? 'consumedAtMs';
