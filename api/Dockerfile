# ── Build stage ────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app

RUN apk add --no-cache python3 make g++

COPY package.json ./
RUN npm install --frozen-lockfile

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# ── Runtime stage ──────────────────────────────────────────────────────────
FROM node:20-alpine AS runtime
WORKDIR /app

# git is required for git-upload-pack / git-receive-pack
RUN apk add --no-cache git tini

# Principle of least privilege
RUN addgroup -S scm && adduser -S scm -G scm

COPY package.json ./
RUN npm install --frozen-lockfile --omit=dev

COPY --from=builder /app/dist ./dist

RUN mkdir -p /data/repos && chown -R scm:scm /data/repos /app

USER scm

EXPOSE 3000

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/app.js"]
