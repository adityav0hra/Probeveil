# Probeveil

Probeveil is a production-oriented security scan control plane for approved web targets. Phase 1 persists real scans, queues isolated passive workers, performs genuine DNS/HTTP/TLS/header/cookie/CSP/CORS and bounded crawl checks, stores evidence with integrity hashes, streams progress and exports JSON/HTML reports.

## Local development

1. Copy `.env.example` to `.env`, replace both secrets and change the seed password.
2. Run `docker compose up --build`.
3. Open `http://localhost:3000` and sign in with `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD`.

For host development, start PostgreSQL and Redis, set their URLs, then run `npm ci`, `npm run db:migrate:dev`, `npm run db:seed`, `npm run dev` and `npm run worker:watch` in separate terminals.

## Database migrations

Database schema changes are versioned in `prisma/migrations`. Create future schema changes with `npm run db:migrate:dev -- --name descriptive_name`, review the generated SQL, commit the migration folder with `prisma/schema.prisma`, then apply migrations in production with `npm run db:migrate`. Do not use `prisma db push` for production schema changes.

## Email provider

Scheduling and contact emails use `RESEND_API_KEY` by default, or `NOTIFICATION_EMAIL_WEBHOOK_URL` / `CONTACT_EMAIL_WEBHOOK_URL` for a custom mail service. Set `NOTIFICATION_DEFAULT_EMAIL`, `CONTACT_ADMIN_EMAIL`, `NOTIFICATION_EMAIL_FROM`, `CONTACT_EMAIL_FROM` and the matching reply-to variables before enabling production alerts.

## Verification

Run `npm run format:check`, `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`, and `npm run test:e2e`. End-to-end tests expect the seeded local services.

## Security notes

Set `SCAN_ALLOWED_HOSTS` to organiser-controlled suffixes. Private targets require both an allowlist match and `SCAN_ALLOW_PRIVATE_NETWORKS=true`. In production, replace default database credentials, authenticate Redis, terminate TLS at the ingress, use a secret manager, encrypt object/database volumes, and enforce target egress policy. See [architecture](docs/ARCHITECTURE.md), [scanner policy](docs/SCANNER_POLICY.md), [operations](docs/OPERATIONS.md) and [API](docs/API.md).
