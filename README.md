# Project Control API — Cloudflare Worker

A separate evidence-gated project workflow API. It does not depend on IRIS project files.

## Runtime
- Cloudflare Workers
- Cloudflare D1 database: `project-control-api-db`
- D1 binding: `DB`
- Bootstrap secret: `BOOTSTRAP_TOKEN` (set in Cloudflare dashboard; never commit secrets)

## Routes
- `GET /_api/health` — public health check
- `GET /openapi.json` — OpenAPI summary
- `POST /_api/admin/bootstrap` — creates the first API key once; requires `X-Bootstrap-Token`
- `POST /_api/control` — requires `X-Project-Control-Key`

## Actions for POST /_api/control
- `{"action":"list"}`
- `{"action":"create","title":"Example","description":"Optional"}`
- `{"action":"detail","runId":"..."}`
- `{"action":"evidence","runId":"...","source":"...","content":"..."}`
- `{"action":"advance","runId":"..."}`
- `{"action":"verify","runId":"..."}`
- `{"action":"audit","runId":"..."}`

Workflow stages: `CONCEPT → DESIGN → EXECUTE → RESULT → VERIFY`. Every stage requires evidence before advancing; completion requires evidence for all stages. Audit events are SHA-256 chained and the verification gate compares stored evidence against the audit log. Completed runs are immutable.

## Bootstrap
After deployment, call `POST /_api/admin/bootstrap` once with header `X-Bootstrap-Token: <value stored as Cloudflare secret>`. Save the returned `apiKey` immediately; it is only returned once. Bootstrap is locked after the first key is created.

## Deployment
Cloudflare Workers Builds reads `wrangler.toml`; it binds the existing D1 database by ID. The API key and bootstrap secret must never be committed to this repository.
