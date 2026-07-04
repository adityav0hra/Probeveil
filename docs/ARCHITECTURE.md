# Probeveil architecture

## Summary

Probeveil is a Next.js control plane backed by PostgreSQL. Auth.js provides admin authentication and server-side role checks. Scan requests are validated and persisted before a minimal job envelope is sent to Redis/BullMQ. A separately built, non-root worker performs bounded passive network checks and reports signed events to a private internal API; it never receives database credentials. Results and immutable evidence metadata are persisted by the control plane. The UI polls a compact scan projection for live progress.

Phase 1 implements real availability, redirect, DNS, TLS, header, cookie, CSP, CORS, robots/sitemap discovery and bounded same-origin crawling. Deeper active tooling belongs to the documented later worker images and is never represented as completed until it really ran.

## Trust boundaries and threat model

1. **Browser to control plane:** hostile input, CSRF and stolen sessions. Mitigations: Auth.js secure cookies, server-side RBAC, same-origin mutations, Zod validation, rate limits, CSP and audit records.
2. **Control plane to queue/database:** forged jobs or state changes. Mitigations: private networks, Redis authentication in production, small typed job envelopes, idempotency keys and database constraints.
3. **Worker to target:** the target is untrusted and may return huge, recursive or malicious content. Mitigations: DNS rebinding checks, allowlist enforcement, redirect revalidation, response/time/route limits, no script execution in Phase 1 and disposable storage.
4. **Worker to control plane:** forged evidence. Mitigations: timestamped HMAC job tokens, scan/job binding, replay window, evidence SHA-256 hashes and audit logging.
5. **Evidence readers:** evidence can contain organiser secrets. Mitigations: admin-only access, no client logs, encryption-ready object store abstraction, access audit, retention policy and isolated report routes.

## Queue and isolation design

`scan.passive` jobs contain a scan ID, normalised URL, mode and signed callback token. Workers run as UID 10001 with a read-only root filesystem, tmpfs `/tmp`, dropped Linux capabilities, process/memory/CPU limits and no host mounts or Docker socket. Workers can reach Redis, the internal callback endpoint and explicitly allowed target networks only. Production deployments split target egress into a dedicated policy-controlled network.

## Scanner integration plan

- Phase 1: built-in HTTP/DNS/TLS passive worker and crawler.
- Phase 2: disposable Playwright, ZAP and versioned Nuclei workers, each returning native artifacts.
- Phase 3: repository association, Semgrep/CodeQL, Trivy/Grype/Syft/OSV, Gitleaks/TruffleHog and IaC workers.
- Phase 4: Schemathesis/stateful API, GraphQL, WebSocket and controlled callback workers.
- Phase 5: advanced correlation, retest and report pipelines plus Kubernetes hardening.

## Folder structure

- `src/app`: App Router pages and authenticated API endpoints
- `src/components`: shared SOC interface components
- `src/lib`: auth, database, validation, queue, scoring and report logic
- `src/worker`: isolated passive scanner process
- `prisma`: schema, migration and seed
- `tests`: unit and end-to-end tests
- `docker`: image entrypoints
- `docs`: architecture, policies, operations and API documentation
- `k8s`: production deployment baseline

## Phase 1 file map

The files above plus the Prisma models, migrations, Auth.js configuration, URL/scope policy, scan/reports APIs, worker checks, dashboard/new scan/live scan/results/finding/report pages, Dockerfiles, Compose topology, tests and operating guides comprise Phase 1. Scanner configuration, attack graph, audit and health pages expose truthful Phase 1 data and clearly label later capabilities unavailable rather than fabricating results.
