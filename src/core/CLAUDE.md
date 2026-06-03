# Core Orchestration Engine

## Responsibilities
- Manage plugin lifecycle and pipeline execution.
- Coordinate bounded system probes.
- Correlate kernel, package, binary, daemon, and intelligence evidence.
- Compute TARA-style risk and remediation guidance.
- Persist local scan history and cache intelligence data.

## Implemented Components
- `src/core/base.py`: Base plugin abstractions.
- `src/core/plugin_manager.py`: Dynamic plugin loading and validation.
- `src/core/pipeline.py`: Pipeline stages and execution flow.
- `src/core/models.py`: Pydantic scan, asset, vulnerability, risk, remediation, and package models.
- `src/core/collector.py`: Async SystemCollector orchestration harness.
- `src/core/risk_engine.py`: TARA-style Impact x Feasibility risk scoring.
- `src/core/remediation.py`: Risk-based remediation recommendations.
- `src/core/storage.py`: SQLite intelligence cache under `memory/data/`.
- `src/core/scan_history.py`: Filesystem-backed scan history under `memory/data/scan_history`.

## Tracking
- Domain progress: `src/core/progress.json`.
- Domain log: `src/core/SESSION_LOG.md`.
- Root source of truth: `tasks/progress.json`.

## Completed Tasks
- [x] Implement `BasePlugin` abstract class.
- [x] Implement `PluginManager` for dynamic loading.
- [x] Implement `Pipeline` orchestrator.
- [x] Define core data models for internal SBOM representation.
- [x] Implement `SystemCollector` for parallel probe orchestration.
- [x] Integrate CPE/CVE/OSV intelligence enrichment.
- [x] Integrate reachability-aware risk scoring.
- [x] Implement remediation guidance.
- [x] Implement scan-history persistence.

## Deferred / Future Work
- [ ] Expand graph persistence for richer attack-path traversal.
- [ ] Add user-defined remediation status workflow persistence.
