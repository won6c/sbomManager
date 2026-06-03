# SBOM Manager TODO Tracking

Last reviewed: 2026-06-03
Source of truth: `tasks/progress.json` -> `active_todo`

## Completed active TODO

| ID | Priority | Area | Status | Task | Implementation |
|---|---|---|---|---|---|
| TODO-PKG-001 | P0 | plugins/packages | completed | Implement Package Probe for high-precision versioning | Added `PackageAsset`, `PackageProbe` for dpkg and Python dist-info metadata, `/api/v1/packages/probe`, and tests. |
| TODO-REMED-001 | P1 | core/api/web | completed | Implement risk-based remediation guidance module | Added `RemediationRecommendation` and `RemediationEngine` that generates P0/P1/P2 actions from exposure, CVE, privilege, and mitigation evidence. |
| TODO-HISTORY-001 | P2 | data/api/web | completed | Replace demo sample data with persisted scan history and saved comparison views | Added filesystem-backed `ScanHistoryStore`, persisted `/scan` results, list/get/compare endpoints, and tests. |

## Deferred TODO

| ID | Priority | Area | Status | Task | Reason |
|---|---|---|---|---|---|
| TODO-RISK-UI-001 | P1 | web/frontend | deferred | Build Risk Visualizer dashboard for prioritized mitigation | Current UI already has risk/reachability/graph; dedicated visualizer is a later enhancement. |
| TODO-NVD-001 | P2 | intelligence/data | deferred | Introduce local full-mirror NVD DB for zero API dependency | SQLite/file caching already reduces API dependency; full NVD mirror is large operational scope. |

## Stale TODO candidates

The following locations contain older unchecked TODO/checklist items that may not match current implementation status. Treat them as stale candidates until reconciled against code/tests:

- `core/CLAUDE.md`
- `api/CLAUDE.md`
- `plugins/*/CLAUDE.md`
- `evaluations/benchmarks/CLAUDE.md`
- `plugins/tasks/progress.json`
- `sbom_manager_project_a5e19c8c.plan.md`

## Tracking rule

- Add/update active work in `tasks/progress.json.active_todo` first.
- Mirror human-readable summaries here when priorities/status/next steps change.
- Do not treat old unchecked checklist items as active unless they are revalidated and copied into `active_todo`.
