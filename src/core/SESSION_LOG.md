# Core Session Log

## 2026-05-05: Core Foundation
- Implemented core plugin abstractions, plugin manager, pipeline stages, exception hierarchy, and internal models.
- Established the harness principle: core coordinates plugin lifecycle and data flow while domain probes remain isolated.

## 2026-05-13: SystemCollector Orchestration
- Added `SystemCollector` for asynchronous coordination of kernel, daemon, binary, and package probes.
- Used `asyncio` with `ThreadPoolExecutor` for bounded parallel probe execution.
- Standardized scan output with Pydantic models.

## 2026-05-18: Intelligence Chain Integration
- Integrated CPE resolution and NVD CVE enrichment into the core collection flow.
- Added synthetic CPE fallback when valid name/version evidence exists.
- Fixed asset model fields required by enrichment and serialization.

## 2026-05-20: TARA Risk Scoring
- Implemented `core/risk_engine.py` using Impact x Feasibility logic.
- Impact is driven by CVSS and privilege context.
- Feasibility is driven by exposure, exploit evidence, mitigations, and later reachability.

## 2026-05-25: Reachability-Aware Pipeline
- Integrated `/proc/[pid]/maps` reachability analysis.
- Added OSV enrichment alongside NVD.
- Updated scan flow to Discovery -> Reachability -> NVD/OSV -> TARA risk.

## 2026-06-03: Remediation and Persistence
- Added `RemediationEngine` to convert risk evidence into P0/P1/P2 remediation actions.
- Added `ScanHistoryStore` for persisted scan history and comparison views.
- Updated storage defaults to use `memory/data/` in the harness layout.

## 2026-06-03: Harness Layout Migration
- Core source moved from `core/` to `src/core/`.
- `pytest.ini` now sets `pythonpath = src`.
- Verification passed via `./scripts/build.sh`, `./scripts/test.sh`, and `./scripts/verify.sh`.
