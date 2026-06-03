# Web Layer

## Responsibilities
- Provide the React/Vite frontend for interactive SBOM Manager review.
- Surface API health, live scan controls, demo fallback, asset inventory, CVE detail, reachability, risk, and SBOM intake.
- Keep UI behavior aligned with the FastAPI contracts in `src/main.py`.

## Current Implementation
- Frontend workspace: `src/web/frontend/`.
- API client: `src/web/frontend/src/api.ts`.
- Typed scan/result models: `src/web/frontend/src/types.ts`.
- Main dashboard: `src/web/frontend/src/App.tsx`.
- Local dev proxy configured in `src/web/frontend/vite.config.ts`.

## Tracking
- Progress: `src/web/progress.json` plus root `tasks/progress.json`.
- Session Log: `src/web/SESSION_LOG.md`.

## Completed Tasks
- [x] React/Vite frontend workspace.
- [x] Typed API client.
- [x] Dashboard with health, live scan, and demo fallback.
- [x] Asset filters and detail panel.
- [x] Attack path relation graph.
- [x] SBOM parser intake panel.
- [x] Vite proxy and backend CORS integration.

## Deferred Tasks
- [ ] Dedicated Risk Visualizer dashboard for prioritized mitigation.
