# syntax=docker/dockerfile:1
#
# Engine Accounts — immagine di produzione.
#
# Costruisce `dist/` con le stesse sorgenti dei test e gira come utente non
# privilegiato. Nessun segreto qui dentro: tutto arriva da env/secret file al
# runtime. Il compose autonomo di EngineAccounts usa la radice del repository
# come contesto; non richiede StreamingEngine.

# --- build --------------------------------------------------------------------
FROM node:24-alpine AS build
WORKDIR /app

# Le dipendenze si installano a parte: il layer dei moduli si riusa finche'
# package-lock.json non cambia.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY scripts ./scripts
COPY migrations ./migrations
RUN npm run build

# `npm prune --omit=dev` toglie TypeScript, vitest e tsx: nell'immagine finale
# non devono esserci.
RUN npm prune --omit=dev

# --- runtime ------------------------------------------------------------------
FROM node:24-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0 \
    ENGINE_ACCOUNTS_JWKS_PATH=/app/var/jwks.json

# `wget` serve al HEALTHCHECK; `tini` e' il PID 1 e inoltra i segnali, cosi'
# `docker stop` ferma Node pulito invece di interromperlo.
RUN apk add --no-cache tini wget

COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/package.json ./package.json
COPY --from=build --chown=node:node /app/migrations ./migrations

# Le chiavi di firma vivono qui: volume, mai nel layer dell'immagine. Il
# permesso 700 e' il minimo perche' `var/jwks.json` contiene chiavi private.
RUN mkdir -p /app/var && chown node:node /app/var && chmod 700 /app/var

USER node
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/server.js"]
