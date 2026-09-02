# Changelog

All notable changes to **Sentinel SOC v2.2** are documented in this file.

The version format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
conventions in spirit. Repository history for this project begins with the
Sentinel SOC v2.2 codebase; there is no prior in-repo version history to
document.

## [2.2.0] — 2026-08-30 → 2026-09-02

Sentinel SOC v2.2 initial open-source release: a full SOC demonstration
platform combining real-time telemetry simulation, incident correlation,
live threat intelligence, MITRE ATT&CK mapping, a grounded AI analyst, and
safe simulated response.

### Added

- **Real-time WebSocket event bus** at `/ws/events`
  (`backend/app/api/websocket.py`):
  - `INITIAL_STATE` snapshot on connect (recent events + open incidents)
  - `EVENT` and `INCIDENT_UPDATE` broadcasts
  - `PING` / `PONG` heartbeat protocol
  - `TRIGGER_SCENARIO` client command for on-demand attack simulation
  - Background simulation loop that continuously generates correlated
    telemetry at startup
- **Simulation engine** (`backend/app/services/simulation_service.py`):
  - 6 multi-step attack scenarios (credential brute force, web CVE
    exploitation, reconnaissance, PowerShell privilege escalation,
    ransomware/lateral movement, data exfiltration)
  - Conflict-free RFC-1918 source IPs and synthetic internal assets
  - Every synthetic event flagged `simulation: true`
- **Correlation & incident engine** (`backend/app/services/correlation_service.py`):
  - Multi-step event clustering into incidents with attack-stage tracking
  - Strict scenario isolation for concurrent/interleaved attack chains
  - SQLite persistence (`sentinel.db`) surviving server restarts
  - Incident lifecycle `OPEN → INVESTIGATING → CONTAINED → RESOLVED`,
    full-text search, and severity/status filtering
- **Threat intelligence services**:
  - NVD 2.0 fetcher with 30-minute TTL cache, CVSS parsing, CWE/CPE
    extraction, CISA KEV cross-referencing, and `data_source` metadata
    (`LIVE_NVD` / `CACHED_NVD` / `FALLBACK`)
  - CISA KEV catalog fetcher with 1-hour TTL cache and ransomware filtering
    (`LIVE_CISA_KEV` / `CACHED_CISA_KEV` / `FALLBACK`)
- **MITRE ATT&CK service** (`backend/app/services/mitre_service.py`):
  - 19-technique Enterprise catalog across 14 tactics
  - Event-type → technique mapping (23 event types)
  - Aggregated `/api/mitre/matrix` with honest `OBSERVED` / `SIMULATED` /
    `NOT_OBSERVED` status derived from real incident/event state
- **Sentinel AI Defensive Analyst** (`backend/app/services/ai_service.py`):
  - Deterministic expert engine default ("Sentinel AI Expert Defensive
    Engine v3.0") with 4-tier evidence breakdown (`observed`, `inferred`,
    `recommended`, `unknown`)
  - Optional OpenAI-compatible LLM path behind `AI_API_KEY` /
    `AI_API_BASE_URL` with strict JSON-schema prompting and defensive-system
    guardrails
  - Risk scoring: `severity_weight × confidence` (0–100) with level
    derivation (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`)
- **Simulated response service** (`backend/app/services/response_service.py`):
  - 4 containment action types (IP BAN, FIREWALL BLOCK,
    CREDENTIAL REVOCATION, HOST ISOLATION)
  - Strictly simulated (`simulation: true`, `status: "SIMULATED SUCCESS"`),
    auditable via SQLite-backed audit log — zero real-world execution
- **Frontend application** (React 19 + Vite + Tailwind v4) with 12 screens:
  Overview command center, Incidents, Incident Investigation, AI Analyst,
  Detections, Live Events, Threat Intelligence, Vulnerabilities,
  MITRE ATT&CK, Response Center, Audit Log, System Health
- **Typed API client** (`frontend/src/lib/sentinel-api.ts`) covering all
  endpoints, WebSocket manager with heartbeat + auto-reconnect, and clearly
  labelled offline fallback datasets

### Improved

- Command-center dashboard revamped with live metrics, severity charts, and
  WebSocket-connected incident tiles (`feat: upgrade command center dashboard`)
- Vulnerability intelligence UI: searchable CVE list, CVSS + KEV badges,
  KEV catalog with ransomware filter, sorting and detail modal
  (`feat: complete day 3 vulnerability intelligence`)
- Derived incident `risk` / `risk_score` fields exposed consistently across
  REST, WebSocket `INITIAL_STATE`, and `INCIDENT_UPDATE` payloads
  (`feat: add derived incident risk scoring`)
- UI accessibility and interaction polish across Sentinel screens
  (`polish: improve Sentinel UI accessibility and interactions`)
- Branding assets separated and bundled (sidebar logo, favicon)

### Security

- HTTP security headers middleware: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `X-XSS-Protection`,
  `Referrer-Policy: strict-origin-when-cross-origin`
- Configurable CORS allow-list (`CORS_ORIGINS`) restricted to localhost and
  `*.vercel.app` origins by default
- Non-root user in the backend Docker image
- Response actions architecturally incapable of modifying real infrastructure
- No credentials or secrets committed; `.env` and database files git-ignored
  (`chore: remove local environment and database files`)

### Testing

- Comprehensive 43-assertion integration suite (`backend/test_suite.py`)
  covering health, dashboard, NVD/KEV, cross-referencing, all 6 attack
  scenarios, correlation isolation, incident lifecycle + SQLite persistence,
  AI evidence contract, WebSocket handshake/broadcast, simulated response
  audit, MITRE aggregation, deterministic risk math, and exact production-bug
  regression (INC-101 scenario isolation)
- Frontend validation scripts: `npm run lint` / `npm run typecheck`
  (`tsc --noEmit`) and `npm run build` (production Vite build)

### Deployment

- Frontend deployed to Vercel: `https://sentinel-soc1.vercel.app/`
- Backend (FastAPI + gunicorn/UvicornWorker) deployed to Render:
  `https://sentinel-soc-api-qpzg.onrender.com` (WebSocket on
  `wss://sentinel-soc-api-qpzg.onrender.com/ws/events`)
- Dockerfile with Python 3.11-slim, non-root user, `PORT`-aware binding
  (`fix: configure backend Docker deployment`, `fix: configure backend Docker
  startup`)
- Vite config updated for Vite 8 (`fix: update vite config for Vite 8`)

### Documentation

- This changelog plus upgraded project README
- Engineering case study (`docs/CASE_STUDY.md`)
- Contribution guide (`CONTRIBUTING.md`)
- Environment variable reference (`.env.example`)
- Screenshot guide for the portfolio presentation (`docs/screenshots/README.md`)

<!-- Link references -->
[2.2.0]: https://github.com/arayan11587kvrsodelhi-oss/sentinel-soc/releases/tag/v2.2.0
