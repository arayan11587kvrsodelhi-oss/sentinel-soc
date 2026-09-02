# Sentinel SOC v2.2 — Engineering Case Study

> A professional write-up of the design, engineering trade-offs, and lessons
> behind building a portfolio-grade educational SOC platform. This document
> describes the system **as implemented** in this repository.

---

## Problem

Security Operations Centers (SOCs) depend on a constant stream of telemetry,
threat intelligence, and analyst judgement. Building one from scratch — even as
a learning system — is an integration problem as much as a security problem:

- Real-time events must reach the operator's screen with minimal latency.
- Raw telemetry noise must be *correlated* into meaningful incidents.
- Intelligence feeds (NVD, CISA KEV) must be normalized and cross-referenced.
- An AI-driven analyst must not be allowed to *guess* without saying so.
- Response actions must be **demonstrable without being dangerous**.

The challenge for this project was to demonstrate all of these behaviours in a
single coherent, deployable system — with live external data where possible,
honest simulation where not, and zero risk to real infrastructure.

## Objective

Sentinel SOC v2.2 was designed to demonstrate:

1. **Real-time security telemetry delivery** over WebSocket.
2. **Multi-stage attack simulation** with scenario isolation (concurrent attack
   chains that never cross-contaminate incident state).
3. **Incident management** with a full lifecycle (`OPEN → INVESTIGATING →
   CONTAINED → RESOLVED`) and SQLite persistence.
4. **Live threat intelligence** — real NIST NVD and CISA KEV feeds with cache,
   fallback, and `data_source` transparency.
5. **MITRE ATT&CK mapping** — every simulated telemetry type maps to an
   Enterprise technique; the matrix reports `OBSERVED` / `SIMULATED` /
   `NOT_OBSERVED` status honestly.
6. **A grounded AI security analyst** that separates *observed* facts from
   *inferred* conclusions from *unknown* factors.
7. **Safe simulated response** — containment actions are recorded and audited
   but never touch real infrastructure.
8. **Production-readiness** — real deployment to Vercel (frontend) and Render
   (FastAPI backend), with a 43-assertion integration test suite.

## Architecture

The system follows a straightforward four-tier flow:

```
User / Browser
      │
      ▼
Sentinel SOC Frontend (React 19 + Vite + Tailwind v4)   [Vercel]
      │  REST (HTTPS)                     │  WebSocket (wss)
      ▼                                   ▼
FastAPI Backend ──────────────► WebSocket Event Bus (/ws/events)
      │
      ├── Simulation Engine        (synthetic telemetry, simulation:true)
      ├── Correlation Engine       (events → incidents, attack stages)
      ├── AI Analyst Service       (expert engine / optional LLM)
      ├── MITRE Service            (technique catalog + event mapping)
      ├── NVD Service              (NIST NVD 2.0, 30-min cache)
      ├── CISA Service             (KEV catalog, 1-hour cache)
      └── Response Service         (simulated actions + audit log)
      │
      ▼
  SQLite (sentinel.db)  +  external feeds (NVD / CISA)
```

Key properties:

- The **WebSocket manager** (`backend/app/api/websocket.py`) broadcasts
  `EVENT` and `INCIDENT_UPDATE` frames to every connected client and delivers
  an `INITIAL_STATE` snapshot on connect.
- A **background simulation loop** generates continuous telemetry, so the UI
  is never empty and the event pipeline is always exercised.
- The **correlation engine** owns incident state and persists it in SQLite so
  incidents and audit logs survive server restarts.

## Engineering Challenges

### Real-time event delivery

Events are generated asynchronously and must reach all clients in order, with
dead connections pruned. The connection manager keeps a set of live
sockets, wraps each `send_text` in error handling, and discards failed
connections during broadcast rather than letting one bad client stall the loop.
The client (`SentinelWsManager`) adds heartbeat pings, 10s API timeouts, and
4-second auto-reconnect.

### Frontend/backend integration

The frontend is a separate Vite app. Integration lessons:

- A single typed client (`frontend/src/lib/sentinel-api.ts`) centralizes every
  endpoint call and WebSocket subscription, with Pydantic-shaped TypeScript
  interfaces mirroring the backend schemas.
- **Offline robustness matters**: every API call has a verified fallback
  payload (`FALLBACK_INCIDENTS`, `FALLBACK_KEV_CATALOG`, …) so the UI renders
  even when the deployed backend is unreachable — and each fallback is clearly
  labelled as such in the UI.

### Threat intelligence normalization

NVD returns CVE records in one shape; CISA KEV returns a different one. The
`VulnerabilityItem` schema unifies both, and the NVD service cross-references
`is_kev`/`kev_details` against the KEV catalog. Both services:

- fetch live data over `httpx`,
- cache with a TTL (1800s NVD, 3600s KEV),
- expose `data_source` ∈ {`LIVE_NVD`/`CACHED_NVD`/`FALLBACK`} and
  {`LIVE_CISA_KEV`/`CACHED_CISA_KEV`/`FALLBACK`},
- fall back to a realistic baseline dataset when the network is unavailable.

### AI evidence boundaries

An AI analyst that "just answers" is dangerous in a SOC context. Sentinel AI
returns a **4-tier evidence contract** (`observed`, `inferred`, `recommended`,
`unknown`) and a deterministic risk score (`severity_weight × confidence`,
clamped 0–100). The default path is a transparent rule-based expert engine
("Sentinel AI Expert Defensive Engine v3.0"); an optional OpenAI-compatible
LLM path exists behind `AI_API_KEY`, gated by a strict JSON-schema prompt.
Nothing in the UI claims the analyst is autonomous — audits remain possible
via `generated_at`, `model`, `source`, and `evidence_count`.

### Simulated response safety

Response actions (IP ban, firewall block, credential revocation, host
isolation) are **purely simulated**: the service writes an audit record to
SQLite and returns `status: "SIMULATED SUCCESS"`, `simulation: true`. There is
no subprocess, no network mutation, no host change. This was a deliberate
boundary: demonstrate the *workflow* of automated containment without the
liability of automated enforcement.

### Production deployment

Two surfaces deploy independently:

- **Frontend** → Vercel (`https://sentinel-soc1.vercel.app/`).
- **Backend** → Render (`https://sentinel-soc-api-qpzg.onrender.com`), run
  with gunicorn + UvicornWorker behind the provided `PORT` (Dockerfile).

The CORS allow-list in `backend/app/main.py` is deliberatelly kept
configurable via `CORS_ORIGINS` and permits `*.vercel.app` origins.

### Asset handling

Every telemetry event and incident references synthetic assets (`auth-gateway`
· `dmz-web-portal` · `db-production-01` · ...) on private RFC-1918 addresses.
No real hostnames, real IPs, or real data are used in the simulation layer.
(An earlier static-copy of the frontend, since replaced, contained invented
CVE identifiers; the current screens load live backend data and the fallback
datasets only contain genuine CVEs. This is called out in the changelog.)

## Key Engineering Decisions

| Decision | Rationale |
|---|---|
| FastAPI + Uvicorn + WebSocket | Native `WebSocket` support and OpenAPI docs with near-zero boilerplate. |
| SQLite for incident/audit state | Zero-ops persistence for a demo system; survives restarts; easily swapped (the path is configurable). |
| Expert engine as the AI default | Deterministic, auditable, free — and it forces the evidence contract to be a first-class citizen. |
| `simulation: true` on every synthetic event | Makes provenance machine-checkable — the test suite asserts it. |
| Data-source labels on every intelligence payload | No silent conflating of live vs fallback data. |
| Separate Vite frontend + typed API client | Clean separation of concerns; deployable to Vercel static hosting. |
## Security Design

### Evidence classification

Every piece of information the system presents falls into one of five classes,
and the UI makes the class visible (`ProvenanceBadge` component):

- **LIVE** — data fetched from a live external source at request time
  (`LIVE_NVD`, `LIVE_CISA_KEV`).
- **CACHED** — data previously fetched live and served from the in-memory TTL
  cache (`CACHED_NVD`, `CACHED_CISA_KEV`).
- **SIMULATED** — synthetic telemetry generated by the simulation engine; every
  event carries `simulation: true` and private-source IPs.
- **DERIVED** — computed by the system itself: correlated incidents, risk
  scores, MITRE matrix status, aggregated dashboard metrics.
- **INFERRED** — AI analyst conclusions explicitly labelled `inferred` (or
  `unknown`), never mixed into the `observed` fact list.

This separation means a reader of any screen can tell *what the system saw*,
*whether it was real or simulated*, and *what was merely guessed*.

### Simulated response safety

The response service deliberately has **no execution surface**:

- Actions are validated and normalized, then recorded to the `response_actions`
  SQLite table.
- Every record returns `simulation: true` and `status: "SIMULATED SUCCESS"`.
- There is no shell access, no firewall API, no EDR connector — by design.
- The wording in the UI ("Simulated ... removes host from network segments") is
  kept visibly hypothetical.

This is the correct architecture for an educational SOC: it demonstrates the
*playbook and audit workflow* end-to-end without granting the demo any real
power.

### Hardening notes

- The HTTP middleware sets `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `X-XSS-Protection`, and a restrictive
  `Referrer-Policy`.
- CORS is configurable via `CORS_ORIGINS` and defaults to localhost + Vercel.
- The Dockerfile runs the backend as a **non-root user**.
- No authentication credential store exists — the system has no secrets to
  leak, and `.env` files are git-ignored.

## Testing Strategy

The test suite (`backend/test_suite.py`, run as `python backend/test_suite.py`)
is a single comprehensive integration run of **43 assertions** against the
live FastAPI app via `TestClient`. It verifies:

| Area | What is checked |
|---|---|
| Root & health | `GET /`, `GET /health` contract |
| Dashboard | Aggregated severity counts, NVD/KEV totals and source labels |
| Vulnerability intelligence | NVD shape, `data_source`, KEV catalog, NVD↔KEV cross-reference (`is_kev`) |
| Simulation | All 6 attack scenarios produce ≥3 steps, all `simulation: true`, private IPs only |
| Correlation | Multi-step chains cluster into one incident; unrelated events isolated |
| Incidents | CRUD, status transitions (OPEN→INVESTIGATING→CONTAINED→RESOLVED→OPEN), search, SQLite persistence across reload |
| AI analyst | Risk score/level contract, 4-tier evidence breakdown, provenance fields |
| WebSocket | Handshake, `INITIAL_STATE`, PING/PONG, live `TRIGGER_SCENARIO` → `INCIDENT_UPDATE` isolation |
| Response | 4 simulated actions, audit log persistence, `simulation: true` enforced |
| MITRE | Matrix ≥15 techniques, tactics coverage, OBSERVED/SIMULATED status |
| Concurrency | Interleaved 2- and 3-scenario isolation, shared IP/target zero-merge, engine restart persistence, exact production-bug reproduction (INC-101) |
| Risk math | Deterministic matrix + clamping edge cases |

The frontend validates with `npm run lint && npm run typecheck && npm run build`
(`tsc --noEmit` plus a production Vite build).

## Deployment

- **Frontend** — `https://sentinel-soc1.vercel.app/`
  Static Vite build (`npm run build`), served by Vercel.
- **Backend** — `https://sentinel-soc-api-qpzg.onrender.com`
  FastAPI app `app.main:app`, gunicorn with `uvicorn.workers.UvicornWorker`
  bound to `${PORT:-8000}` (Dockerfile). Swagger UI at `/docs`.
- **WebSocket** — `wss://sentinel-soc-api-qpzg.onrender.com/ws/events`
- **Repository** — `https://github.com/arayan11587kvrsodelhi-oss/sentinel-soc`

The frontend resolves the production API/WS URLs automatically when not running
on `localhost`, and both can be overridden with `VITE_SENTINEL_API_URL` /
`VITE_SENTINEL_WS_URL`.

## Lessons Learned

1. **Honest provenance is a feature, not an afterthought.** Labelling every
   event, CVE entry, and AI claim with its origin made the system more credible
   and made testing trivially easy to reason about.
2. **Simulation needs isolation guarantees.** Without explicit scenario IDs and
   isolation rules, concurrent attack chains silently merged incidents and
   corrupted `attack_stage` — this exact bug was reproduced in production,
   fixed, and pinned by tests 35–41. Isolation became a first-class test
   concern.
3. **A deterministic "analyst" is the right default.** The expert engine always
   works, never costs API tokens, and produces content the test suite can
   assert on. The optional LLM path is an enhancement, not a dependency.
4. **Frontend fallbacks are UX, not shortcuts.** When the backend is down, the
   dashboard still renders — but every fallback is visibly labelled so no one
   mistakes cached/mock data for live data.
5. **Version skew is a real risk in a two-repo layout.** The git history shows
   earlier UI screens carrying invented CVE IDs that did not exist in the
   backend dataset. Centralizing data access behind one typed client and
   removing fake CVEs from the UI closed that gap.
6. **Deploy early, test against production.** The WebSocket client with
   reconnect, the CORS list, and the Render health check were all shaped by
   actually running the app on two platforms.

## Future Improvements

Only genuine, not-yet-implemented ideas — nothing here exists in the current
codebase:

- **Real authentication/authorization** (e.g. JWT roles for analyst vs. SOC
  manager) — the app currently has no auth layer by design.
- **ML-based anomaly scoring** alongside the deterministic severity×confidence
  risk model.
- **Expanded MITRE coverage** beyond the current 19 techniques.
- **Live event replay / export** (CSV/JSON) for post-incident review.
- **Deeper CVE enrichment** — exploit-db / EPSS scoring integration into the
  intelligence layer.
- **Multi-tenant deployments** and horizontal scaling of the WebSocket bus
  (persistent pub/sub instead of in-memory broadcast).
