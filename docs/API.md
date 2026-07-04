# API

All public endpoints require an Auth.js session. `POST /api/scans` accepts exactly `{ "url": string, "mode": "QUICK" | "FULL" | "MAXIMUM" }`. `GET /api/scans/:id` returns live persisted state. `POST /api/scans/:id/cancel` cancels a scan. `GET /api/scans/:id/report?format=json|html` exports a report. `GET /api/findings/:id/evidence` exports complete finding evidence.

Worker callback endpoints are private and require a time-bound HMAC token bound to the scan ID. They must never be published through ingress.
