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
RUN addgroup -g 10001 probeveil && adduser -D -u 10001 -G probeveil probeveil
COPY --from=build --chown=probeveil:probeveil /app/.next/standalone ./
COPY --from=build --chown=probeveil:probeveil /app/.next/static ./.next/static
COPY --from=build --chown=probeveil:probeveil /app/prisma ./prisma
USER probeveil
EXPOSE 3000
CMD ["node", "server.js"]

FROM deps AS worker
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -g 10001 probeveil && adduser -D -u 10001 -G probeveil probeveil
COPY --chown=probeveil:probeveil src ./src
COPY --chown=probeveil:probeveil tsconfig.json package.json ./
USER probeveil
CMD ["npm", "run", "worker"]
