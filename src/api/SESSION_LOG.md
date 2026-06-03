# API Session Log

## 2026-05-13: FastAPI Scan Harness
- Implemented `src/main.py` as the FastAPI entrypoint.
- Added `/health` for liveness checks.
- Added `/scan` to trigger `SystemCollector.collect()` with user-supplied `binary_scan_paths`.
- Verified request flow: web/API request -> core collection -> JSON response.

## 2026-05-20: Serialization and Risk API Stabilization
- Fixed scan response recursion/serialization issues by returning JSON-compatible Pydantic payloads.
- Confirmed CVSS-enriched vulnerabilities and TARA risk scores are represented in scan output.

## 2026-05-25: Granular Intelligence Endpoints
- Added targeted endpoints for CPE, CVE, reachability, OSV, and SBOM parsing.
- Split monolithic analysis functions into API-callable intelligence checks for demos and debugging.

## 2026-05-27: Frontend Compatibility
- Added CORS support for local Vite frontend origins.
- Fixed API v1 CPE/CVE handlers to match current plugin contracts.
- Verified `/health`, Vite proxy `/health`, CPE resolution, SBOM parsing, and scan smoke requests.

## 2026-06-03: Package Probe and Scan History APIs
- Added `/api/v1/packages/probe` for scoped package manifest probing.
- Added `/api/v1/scans`, `/api/v1/scans/{scan_id}`, and `/api/v1/scans/compare/{base_scan_id}/{target_scan_id}`.
- FastAPI TestClient smoke checks for package probe and scan-history endpoints returned HTTP 200.

## 2026-06-03: Harness Layout Migration
- API source moved from `main.py`/`api/` to `src/main.py` and `src/api/`.
- Runtime command now uses `PYTHONPATH=$PWD/src uvicorn main:app`.
- Import smoke check reported app title `SBOM Manager API` and 16 routes.
