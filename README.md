# SENTINEL SOC
Full-stack educational Security Operations Center starter.

## Stack
React + TypeScript + Vite | Python + FastAPI | SQLite (easy local default) | WebSockets | NVD + CISA KEV | optional AI provider.

### Run backend
cd backend
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

### Run frontend
cd frontend
npm install
npm run dev

Frontend: http://localhost:5173
API docs: http://localhost:8000/docs

IMPORTANT: simulator events are synthetic and labeled SIMULATION. Public intelligence is fetched from public security feeds. Do not represent synthetic events as real attacks.
