# API Layer (FastAPI)

## Responsibilities
- Expose orchestration triggers for full scans and targeted intelligence lookups.
- Serve scan history, package probe results, vulnerability intelligence, and SBOM parser results to the frontend.
- Keep endpoint contracts aligned with plugin implementations and frontend API client types.

## Implemented Endpoints
- `GET /health`
- `POST /scan`
- `POST /api/v1/intelligence/cpe`
- `POST /api/v1/intelligence/cve`
- `POST /intelligence/cache/refresh`
- `GET /intelligence/reachability`
- `GET /intelligence/osv`
- `POST /intelligence/sbom/parse`
- `POST /api/v1/packages/probe`
- `GET /api/v1/scans`
- `GET /api/v1/scans/{scan_id}`
- `GET /api/v1/scans/compare/{base_scan_id}/{target_scan_id}`

## Tracking
- Domain progress: `src/api/progress.json`.
- Domain log: `src/api/SESSION_LOG.md`.
- Root source of truth: `tasks/progress.json`.

## Completed Tasks
- [x] Setup FastAPI basic structure.
- [x] Implement scan trigger endpoint.
- [x] Implement health endpoint.
- [x] Implement intelligence endpoints for CPE/CVE/reachability/OSV/SBOM.
- [x] Implement package probe endpoint.
- [x] Implement scan history list/detail/compare endpoints.
- [x] Add local frontend CORS/proxy compatibility.

## Deferred Tasks
- [ ] API authentication and rate limiting.
- [ ] User-defined remediation status update endpoint.
