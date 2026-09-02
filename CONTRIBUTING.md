# Contributing to Sentinel SOC v2.2

Thanks for your interest in contributing. Every command below is verified to
work in this repository (Windows PowerShell and Linux/macOS compatible).

## Repository layout

```
sentinel-soc-v2.2/
├── backend/     FastAPI application (app/main.py, app/api, app/services)
├── frontend/    React 19 + Vite + Tailwind v4 application
├── requirements.txt   Backend Python dependencies
├── Dockerfile   Backend container (Python 3.11)
└── README.md    Project documentation
```

## Local setup

### Prerequisites

- Node.js 20+ and npm (frontend)
- Python 3.11+ (backend)
- Git

### 1. Clone and install

```powershell
git clone https://github.com/arayan11587kvrsodelhi-oss/sentinel-soc.git
cd sentinel-soc
```

### 2. Backend setup

```powershell
python -m pip install -r requirements.txt
```

Copy the environment reference (optional — everything works with defaults):

```powershell
Copy-Item .env.example .env
```

Run the backend (from the repository root so `app.*` imports resolve):

```powershell
cd backend
uvicorn app.main:app --reload --port 8000
```

Interactive API docs: http://localhost:8000/docs

### 3. Frontend setup

```powershell
cd frontend
npm install
```

Create the frontend environment file (optional; defaults already point at the
production backend when not on `localhost`):

```powershell
Copy-Item .env.example .env.local
```

### 4. Run the frontend

```powershell
npm run dev
```

The Vite dev server starts (default http://localhost:5173) and proxies to the
backend at `http://localhost:8000` when running locally.

## Environment variables

See `.env.example` for the complete documented list:

| Variable | Side | Purpose |
|---|---|---|
| `VITE_SENTINEL_API_URL` | Frontend | REST API base URL (default: `http://localhost:8000` locally, Render URL in production) |
| `VITE_SENTINEL_WS_URL` | Frontend | WebSocket URL (default: `ws://localhost:8000/ws/events` locally) |
| `AI_API_KEY` | Backend | Optional LLM key; when absent the built-in expert engine is used |
| `AI_API_BASE_URL` | Backend | Optional OpenAI-compatible chat completions endpoint |
| `AI_MODEL` | Backend | LLM model name (default `gpt-3.5-turbo`) |
| `NVD_API_KEY` | Backend | Optional NVD API key to raise rate limits |
| `SQLITE_DB_PATH` | Backend | Override SQLite path (default `backend/sentinel.db`) |
| `CORS_ORIGINS` | Backend | Extra comma-separated CORS origins |

**Never commit real tokens or API keys.**

## Development commands

| Action | Command |
|---|---|
| Frontend dev server | `cd frontend && npm run dev` |
| Backend dev server | `cd backend && uvicorn app.main:app --reload --port 8000` |
| Frontend lint (TS) | `cd frontend && npm run lint` |
| Frontend typecheck | `cd frontend && npm run typecheck` |
| Frontend build | `cd frontend && npm run build` |
| Backend test suite | `python backend/test_suite.py` (run from repo root) |
| Format | `cd frontend && npm run format` |

## Testing

- **Backend**: run `python backend/test_suite.py` from the repository root.
  The 43-assertion integration suite uses FastAPI `TestClient` and requires no
  external services (NVD/KEV fall back gracefully).
- **Frontend**: `npm run lint` and `npm run typecheck` (both `tsc --noEmit`),
  plus `npm run build` to verify the production bundle.

## Build & deploy notes

Frontend production build:

```powershell
cd frontend
npm run build
# output in frontend/dist — deploy to Vercel/static hosting
```

Backend container:

```powershell
docker build -t sentinel-soc .
docker run -p 8000:8000 sentinel-soc
```

The Dockerfile binds gunicorn to `${PORT:-8000}` (Render provides `PORT`).

## Contribution workflow

1. Create a branch: `git checkout -b feat/your-feature`
2. Make focused changes and keep the existing architecture intact
3. Run backend tests + frontend lint/typecheck/build
4. Commit with a descriptive message:

```text
feat: add <feature>
fix: correct <behaviour>
docs: update <documentation>
```

5. Open a pull request against `main`.

## Do / don't

- **Do** preserve WebSocket protocol, API contracts, and the incident
  lifecycle — they are pinned by the test suite.
- **Do** keep every simulated event flagged `simulation: true`.
- **Don't** introduce real credentials, tokens, or PII into the repo.
- **Don't** add UI/fake data where the backend already provides the real
  contract — prefer extending the typed client in
  `frontend/src/lib/sentinel-api.ts`.
