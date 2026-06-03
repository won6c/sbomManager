# SBOM Manager - Exploit Surface Analyzer

SBOM Manager is a security-oriented orchestration framework that turns passive SBOM collection into active exploit surface analysis. It correlates kernel state, binary mitigations, package vulnerabilities, daemon exposure, and runtime reachability to prioritize realistic attack paths.

## What it does

- Collects host security assets: kernel, binaries, packages, daemons, and third-party components.
- Resolves package and binary metadata into CPE/PURL identifiers.
- Enriches assets with CVE intelligence from NVD and OSV.
- Scores risk using exploitability context instead of CVE count alone.
- Persists scan history and vulnerability cache data for repeat analysis.
- Provides a FastAPI backend and a React/Vite frontend for interactive review.

## Architecture

```text
User -> Frontend -> API -> Core Correlation Engine
                         -> Kernel Probe
                         -> Binary Probe
                         -> Package Probe
                         -> Daemon Probe
                         -> Intelligence Layer
                              -> CPE Resolver
                              -> CVE Providers
                              -> Risk Scoring Engine
                              -> Attack Path Insights
                         -> Persistence
```

## Repository layout

```text
.
├── main.py                 # FastAPI entrypoint
├── core/                   # Collector, models, storage, risk engine, pipeline
├── plugins/                # Kernel, binary, package, daemon, SBOM, intelligence probes
├── tests/                  # Unit, integration, and verification scripts
├── web/frontend/           # React + Vite frontend
├── data/                   # Local cache/test data
├── repo_skills/            # Project-local workflow skills
└── slide/                  # Presentation materials
```

## Core principles

- Correlation over collection: assets are modeled as related graph nodes, not isolated rows.
- Exploitability focus: risk reflects reachability, exposure, and mitigations such as PIE, NX, RELRO, KASLR, SMEP, and SMAP.
- User-defined scope: binary scanning is path-limited to avoid system-wide lag.
- Graceful degradation: non-root execution is supported and restricted findings are marked explicitly.

## Backend quick start

Requires Python 3.10+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn pydantic loguru requests python-dotenv pyelftools psutil networkx pytest
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Run a scoped scan:

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"binary_scan_paths":["/bin","/usr/bin"],"persist":true}'
```

## Frontend quick start

```bash
cd web/frontend
npm install
npm run dev
```

The frontend expects the API to be reachable from local development origins such as `http://localhost:5173`.

## Useful API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Backend health check |
| POST | `/scan` | Run full system collection with path-limited binary scan |
| POST | `/api/v1/intelligence/cpe` | Resolve component name/version to CPE |
| POST | `/api/v1/intelligence/cve` | Query CVEs for a CPE |
| POST | `/intelligence/cache/refresh` | Refresh or clean intelligence cache |
| GET | `/intelligence/reachability` | Check whether a binary path is loaded in process memory |
| GET | `/intelligence/osv` | Query OSV vulnerabilities by PURL |
| POST | `/intelligence/sbom/parse` | Parse a CycloneDX JSON SBOM file from a local path |
| POST | `/api/v1/packages/probe` | Probe package manifests in scoped paths |
| GET | `/api/v1/scans` | List persisted scan history |
| GET | `/api/v1/scans/{scan_id}` | Fetch a persisted scan result |
| GET | `/api/v1/scans/compare/{base_scan_id}/{target_scan_id}` | Compare two persisted scans |

## Testing

```bash
pytest tests
```

Targeted verification scripts are also available under `tests/verify_*.py` for probing individual components such as kernel, daemons, binaries, CPE resolution, CVSS extraction, and scan results.

## Risk model

The project prioritizes real-world exploitability through a staged scoring model:

```text
Base Score (max CVSS) -> Exposure Multiplier (accessibility/reachability) -> Mitigation Factor (defense mechanisms)
```

This aligns with the project TARA direction: risk is treated as `Impact x Feasibility`, adapted for PC/server attack-surface analysis.

## Notes

- Some probes return richer data when run with elevated privileges.
- Restricted fields should degrade to explicit privilege-restricted states rather than failing the full scan.
- Binary scanning should remain scoped to user-provided paths.
- Local cache and generated scan data should not be treated as authoritative security evidence without verification.
