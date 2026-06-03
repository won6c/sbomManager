# Project Context

SBOM Manager is a harness-engineered exploit surface analyzer. It transforms passive SBOM collection into active attack-surface analysis by correlating host assets, vulnerability intelligence, exposure, mitigations, and runtime reachability.

## Current Harness Layout

```text
src/ -> runnable source code
evaluations/benchmarks/ -> tests and verification scripts
evaluations/reports/ -> slides and reports
tasks/ -> progress, TODO, and done logs
plans/ -> implementation plans
skills/ -> project-local reusable workflows
docs/ -> architecture, requirements, threat model, decisions
memory/data/ -> local cache, scan history, and curated test fixtures
```

## Core Flow

```text
API request -> SystemCollector -> Kernel/Daemon/Binary/Package probes -> CPE/PURL resolution -> NVD/OSV enrichment -> reachability -> TARA risk -> remediation -> scan history
```

## Source of Truth
- Primary progress: `tasks/progress.json`.
- Human TODO view: `tasks/todo/TODO_TRACKING.md`.
- Historical log: `tasks/done/SESSION_LOG.md`.
- Domain progress files mirror the relevant parts of root progress and should not diverge.
