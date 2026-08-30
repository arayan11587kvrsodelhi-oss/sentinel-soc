# Sentinel SOC v2.2

This package combines the **new Figma Make frontend** with the **older working Sentinel backend**.

## Structure
- `frontend/` — Figma v2.2 React/Vite UI, including `.figma/make/site.json` required by its Vite configuration.
- `backend/` — existing Sentinel FastAPI backend.
- Docker/requirements/support files — retained from the older project.

## Production backend
API:
https://sentinel-soc-bozv.onrender.com

WebSocket:
wss://sentinel-soc-bozv.onrender.com/ws/events

The frontend API helper is in `frontend/src/lib/sentinel-api.ts`.

## Local frontend
```powershell
cd frontend
npm install
npm run dev
```

## Local backend
```powershell
cd backend
python -m pip install -r ../requirements.txt
```
Then start FastAPI using the entry point/configuration from `backend/app/main.py`.

Do not delete `.figma/` from the frontend: the exported `vite.config.ts` imports `.figma/make/site.json`.
