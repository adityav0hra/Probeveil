# Scanner policy

Phase 1 is passive and bounded. It issues GET/HEAD/OPTIONS requests, parses public HTML, follows redirects only after scope validation, and never submits forms. Maximum response size is 2 MiB, crawl routes are capped by mode, and every request has a timeout. Private, loopback and link-local addresses are denied unless `SCAN_ALLOW_PRIVATE_NETWORKS=true` and the hostname matches `SCAN_ALLOWED_HOSTS`. Every redirect is resolved and checked again to reduce DNS-rebinding and open-redirect escape risk.

External discoveries are recorded but never actively tested. Destructive payloads, denial-of-service templates and uncontrolled callbacks are forbidden in every phase.
