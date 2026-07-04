FROM node:22.15.1-alpine3.21 AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci

FROM deps AS build
COPY . .
RUN npx prisma generate && npm run build

FROM node:22.15.1-alpine3.21 AS web
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -g 10001 webguard && adduser -D -u 10001 -G webguard webguard
COPY --from=build --chown=webguard:webguard /app/.next/standalone ./
COPY --from=build --chown=webguard:webguard /app/.next/static ./.next/static
COPY --from=build --chown=webguard:webguard /app/prisma ./prisma
USER webguard
EXPOSE 3000
CMD ["node", "server.js"]

FROM deps AS worker
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -g 10001 webguard && adduser -D -u 10001 -G webguard webguard
COPY --chown=webguard:webguard src ./src
COPY --chown=webguard:webguard tsconfig.json package.json ./
USER webguard
CMD ["npm", "run", "worker"]
