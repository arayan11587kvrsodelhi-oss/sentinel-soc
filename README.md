# SENTINEL SOC — Security Operations Center

> **Threat intelligence. Under control.**
> Production-grade educational Security Operations Center (SOC) dashboard integrating real public vulnerability intelligence (NIST NVD + CISA KEV), realistic real-time telemetry simulation, multi-event correlation, incident lifecycle management, and Sentinel AI defensive analysis mapped to the MITRE ATT&CK® framework.

---

## 🏛️ System Architecture

```text
                    SENTINELSOC
                         │
                   Web Dashboard (React + Vite + TypeScript)
                         │
                  WebSocket Event Bus
                         │
          ┌──────────────┼──────────────┐
          │              │              │
          ▼              ▼              ▼
      Simulation     Threat Intel   Vulnerability
        Engine          Feeds           Intel
    (Attack Chains)  (CISA KEV)       (NIST NVD)
          │              │              │
          └──────────────┼──────────────┘
                         │
                         ▼
                 Correlation Engine
             (Multi-step Pattern Matching)
                         │
                         ▼
                  Incident Engine
           (Status: OPEN / INVESTIGATING /
               CONTAINED / RESOLVED)
                         │
                         ▼
                    Sentinel AI
              (Defensive Triage Engine)
                         │
              ┌──────────┼──────────┐
              │          │          │
             Risk     MITRE      Response
          Assessment  Mapping   Playbooks
                         │
                         ▼
                  SOC Dashboard
```

---

## ✨ Key Capabilities

1. **Real Public Threat Intelligence (NIST NVD + CISA KEV)**:
   - Fetches live CVEs from NIST NVD API 2.0 with automatic CVSS v3.1/v4.0 scoring, CWE definitions, and affected CPE products.
   - Live ingestion of the official **CISA Known Exploited Vulnerabilities (KEV)** catalog (~1,600+ CVEs).
   - Instant cross-referencing: Every NVD record is enriched with KEV exploit indicators, date added, remediation due dates, and ransomware campaign usage.
   - Resilient in-memory TTL caching with high-fidelity offline fallback data.

2. **Real-Time WebSocket Event Bus & Telemetry Broadcaster**:
   - Resilient WebSocket connection manager with heartbeat ping/pong latency measurement, automatic exponential backoff, and initial state replay.
   - Streams synthetic security events (`BRUTE_FORCE`, `EXPLOIT_ATTEMPT`, `PORT_SCAN`, `SUSPICIOUS_LOGIN`, `RANSOMWARE_ACTIVITY`, `DATA_EXFILTRATION`).
   - Clearly labeled with `simulation: true` and private test IP addresses (`10.0.x.x` / `192.168.x.x`).

3. **Realistic Multi-Step Simulation Engine**:
   - Generates coordinated multi-step attack chains (Credential Brute Force, Web Vulnerability Exploitation, Ransomware Deployment, Database Exfiltration).
   - On-demand scenario triggers for educational demonstrations.

4. **Event Correlation & Incident Management**:
   - Stateful correlation engine detects attack patterns across sliding time windows and links related telemetry into actionable **Incidents**.
   - Full lifecycle workflow: `OPEN` → `INVESTIGATING` → `CONTAINED` → `RESOLVED` directly synced with backend APIs.
   - Correlation confidence meters (0-100%) and interactive visual event timelines.

5. **Sentinel AI Defensive Analyst**:
   - Zero-configuration rule-based expert heuristic engine provides deep defensive triage, risk scoring (0-100), and MITRE ATT&CK mapping out of the box.
   - Clear separation between **Observed Facts (Ground Truth)** and **AI Inference (Probabilistic Analysis)**.
   - Actionable 3-tier response: Immediate Containment Playbook, Forensic Investigation Steps, Long-Term Hardening.
   - Optional external LLM integration via standard OpenAI-compatible API (`AI_API_KEY`, `AI_API_BASE_URL`, `AI_MODEL`).

6. **Interactive SOC Forensics UI**:
   - **Event Detail Drawer**: Complete network flow (Source IP → Target Asset:Port), raw payloads, and MITRE context.
   - **Incident Investigation Drawer**: Chronological visual event timeline with connecting nodes and status controls.
   - **Vulnerability Dossier Modal**: Comprehensive CVE details, CVSS breakdown, CISA KEV dates, and official advisories.

---

## 📡 API Reference

### Health & Aggregation
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | API status and metadata |
| `GET` | `/health` | Healthcheck and active WebSocket connections |
| `GET` | `/api/dashboard` | Aggregated SOC counts (critical, high, active incidents, cached CVEs) |

### Vulnerability Intelligence
| Method | Endpoint | Query Parameters | Description |
|---|---|---|---|
| `GET` | `/api/vulnerabilities` | `search`, `severity`, `kev_only`, `limit`, `offset`, `force_refresh` | Enriched NVD CVEs cross-referenced with CISA KEV |
| `GET` | `/api/vulnerabilities/kev` | `search`, `ransomware_only`, `limit`, `offset`, `force_refresh` | Official CISA KEV catalog |

### Incident Management
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/incidents` | List active correlated incidents (`status`, `severity`, `search` filters) |
| `GET` | `/api/incidents/{id}` | Detailed incident investigation dossier |
| `PATCH` | `/api/incidents/{id}/status` | Update incident status (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`) |
| `POST` | `/api/incidents/{id}/ai-triage` | Trigger Sentinel AI defensive triage on incident |

### Telemetry & AI Analyst
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/threats` | List recent simulated telemetry events |
| `POST` | `/api/ai/analyze` | Sentinel AI defensive triage on arbitrary event/telemetry payload |
| `WS` | `/ws/events` | Real-time WebSocket event bus and scenario trigger bus |

---

## ⚙️ Environment Variables

### Backend (`backend/.env`)
```env
# Optional SQLite connection string
DATABASE_URL=sqlite:///./sentinel.db

# National Vulnerability Database API Key (Optional)
NVD_API_KEY=

# CORS Allowed Origins (Comma-separated)
CORS_ORIGINS=https://sentinel-soc-gamma.vercel.app,http://localhost:5173,http://localhost:5174

# Optional LLM Integration (Falls back to built-in expert rule engine if unset)
AI_API_KEY=
AI_API_BASE_URL=https://api.openai.com/v1/chat/completions
AI_MODEL=gpt-4o-mini
```

### Frontend (`frontend/.env`)
```env
# Backend REST API URL (Defaults to http://localhost:8000 in dev)
VITE_API_BASE_URL=http://localhost:8000

# Backend WebSocket URL (Defaults to ws://localhost:8000/ws/events in dev)
VITE_WS_BASE_URL=ws://localhost:8000/ws/events
```

---

## 🚀 Local Development Setup

### 1. Prerequisites
- **Node.js**: v18+ (tested on Node v20/v24)
- **Python**: v3.10+ (tested on Python 3.11/3.14)

### 2. Backend Setup (PowerShell / Windows)
```powershell
cd sentinel-soc/backend

# Create & activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run backend server
uvicorn app.main:app --reload --port 8000
```

*(For Linux/macOS, use `source .venv/bin/activate`)*

### 3. Frontend Setup
```powershell
cd sentinel-soc/frontend

# Install packages
npm install

# Run Vite dev server
npm run dev
```

- **Frontend Dashboard**: `http://localhost:5173`
- **Backend API & Swagger Docs**: `http://localhost:8000/docs`
- **Health Check**: `http://localhost:8000/health`

### 4. Run Automated Test Suite
```powershell
cd sentinel-soc/backend
.\.venv\Scripts\python.exe test_suite.py
```

---

## 🚢 Production Deployment

### Frontend (Vercel)
1. Link repository to Vercel (Root Directory: `sentinel-soc/frontend`).
2. Set Environment Variables in Vercel:
   - `VITE_API_BASE_URL`: `https://your-backend.onrender.com`
   - `VITE_WS_BASE_URL`: `wss://your-backend.onrender.com/ws/events`
3. Deploy. Build command: `npm run build`. Output directory: `dist`.

### Backend (Render / Docker / VPS)
1. Build container using `Dockerfile` in `sentinel-soc/backend`.
2. Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`.
3. Configure `CORS_ORIGINS` to match your Vercel deployment domain.

---

## 🛡️ Educational Disclaimer

> **IMPORTANT**: SentinelSOC is an educational platform. All telemetry events generated by the simulation engine are strictly **synthetic** and labeled `simulation: true`. Attacker source IPs utilize private, non-routable address blocks (`10.0.x.x`, `192.168.x.x`, `172.16.x.x`). Threat and vulnerability intelligence is sourced from publicly accessible feeds provided by NIST and CISA.

