# Production deployment, backup and recovery

Use managed PostgreSQL with encrypted storage and point-in-time recovery, authenticated Redis with append-only persistence, and TLS at every service boundary. Store `AUTH_SECRET` and `WORKER_SIGNING_SECRET` in a secret manager and rotate by draining queues, deploying both control plane and workers with the new secret, then invalidating prior jobs.

Back up PostgreSQL daily and before migrations. Verify restore monthly into an isolated environment. Evidence artifacts should use versioned object storage with server-side encryption, lifecycle retention and a separate backup policy. Restore order is PostgreSQL, evidence objects, Redis only if in-flight jobs must resume; otherwise mark interrupted jobs failed and retest.

## Database migrations

Probeveil uses Prisma Migrate for auditable schema changes. The committed baseline migration represents the current production schema and has been marked as applied on existing local and production databases. For new schema work:

1. Update `prisma/schema.prisma`.
2. Run `npm run db:migrate:dev -- --name <change_name>` against a development database.
3. Review the generated SQL in `prisma/migrations`.
4. Run `npm run db:status` and the test/build verification suite.
5. Back up production, then run `npm run db:migrate` with production environment variables before deploying the matching application build.

Avoid `prisma db push` outside disposable development databases because it bypasses migration review and does not create a versioned rollback/audit trail.

Monitor scan failure rate, queue age, worker restarts, stage timeouts, evidence hash failures and storage capacity. The Compose file is a local/single-host baseline; production should use the Kubernetes manifests and network policies, external secrets, managed data services and restricted ingress.
