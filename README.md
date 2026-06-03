# SBOM Manager - Exploit Surface Analyzer

SBOM Manager is a security-oriented orchestration framework that turns passive SBOM collection into active exploit surface analysis. It correlates kernel state, binary mitigations, package vulnerabilities, daemon exposure, and runtime reachability to prioritize realistic attack paths.

## What it does

- Collects host security assets: kernel, binaries, packages, daemons, and third-party components.
- Resolves package and binary metadata into CPE/PURL identifiers.
- Enriches assets with CVE intelligence from NVD and OSV.
- Scores risk using exploitability context instead of CVE count alone.
- Persists scan history and vulnerability cache data for repeat analysis.
- Provides a FastAPI backend and a React/Vite frontend for interactive review.

## Harness architecture

```text
User -> Frontend -> API -> Core Harness / SystemCollector
                         -> Kernel Probe
                         -> Binary Probe
                         -> Package Probe
                         -> Daemon Probe
                         -> Intelligence Layer
                              -> CPE Resolver
                              -> CVE Providers
                              -> Reachability Analyzer
                              -> Risk Scoring Engine
                              -> Remediation Engine
                         -> Persistence
```

## Repository layout

```text
.
├── AGENTS.md                  # Agent/project operating instructions
├── README.md                  # Project overview and commands
├── docs/                      # Architecture, requirements, threat model, decisions
│   ├── architecture/
│   ├── requirements/
│   ├── threat-model/
│   └── decisions/
├── skills/                    # Project-local reusable workflows actually used by this repo
│   └── tara/
├── plans/                     # Active/completed implementation plans
├── tasks/                     # TODO/doing/done/progress tracking
├── scripts/                   # Repeatable build/test/verify commands
├── evaluations/               # Benchmarks, verification tests, reports, slides
│   ├── benchmarks/
│   └── reports/
├── memory/                    # Project context, lessons, local cache/runtime data
└── src/                       # Runnable source code
    ├── main.py                # FastAPI entrypoint
    ├── core/                  # Collector, models, storage, risk engine, pipeline
    ├── plugins/               # Kernel, binary, package, daemon, SBOM, intelligence probes
    ├── api/                   # API domain docs/progress
    └── web/frontend/          # React + Vite frontend
```

## Core principles

- Correlation over collection: assets are modeled as related graph nodes, not isolated rows.
- Exploitability focus: risk reflects reachability, exposure, and mitigations such as PIE, NX, RELRO, KASLR, SMEP, and SMAP.
- User-defined scope: binary scanning is path-limited to avoid system-wide lag.
- Graceful degradation: non-root execution is supported and restricted findings are marked explicitly.

## Full-stack launch

Run backend and frontend together:

```bash
./scripts/launch.sh
```

Defaults:

```text
Backend:  http://127.0.0.1:8000
Frontend: http://127.0.0.1:5173
```

Optional overrides:

```bash
BACKEND_PORT=8001 FRONTEND_PORT=5174 ./scripts/launch.sh
```

## Backend quick start

Requires Python 3.10+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH="$PWD/src:${PYTHONPATH:-}"
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
cd src/web/frontend
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

## Testing and verification

```bash
./scripts/build.sh
./scripts/test.sh
./scripts/verify.sh
```

Targeted verification scripts are under `evaluations/benchmarks/verify_*.py` for probing individual components such as kernel, daemons, binaries, CPE resolution, CVSS extraction, and scan results.

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
- Local cache and generated scan data under `memory/data/` should not be treated as authoritative security evidence without verification.
