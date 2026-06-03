# Data and Memory Layer

## Responsibilities
- Store local runtime/cache data for intelligence lookups and scan history.
- Keep generated cache data separate from source code and curated fixtures.
- Support repeatable demos without making cache output authoritative security evidence.

## Current Paths
- SQLite CVE/intelligence cache: `memory/data/intelligence_cache.db`.
- Scan history: `memory/data/scan_history/`.
- Curated CPE test fixtures: `memory/data/test_cpe_cache/`.
- Generated scan result exports: `memory/data/results/`.

## Implemented Components
- `src/core/storage.py`: `CVEStorage` SQLite cache with TTL.
- `src/core/scan_history.py`: `ScanHistoryStore` filesystem persistence.
- `.gitignore`: excludes generated runtime cache outputs while preserving curated fixtures.

## Tracking
- Domain log: `memory/data/SESSION_LOG.md`.
- Root source of truth: `tasks/progress.json`.

## Completed Tasks
- [x] Select local cache/persistence approach.
- [x] Implement SQLite intelligence cache.
- [x] Implement scan-history storage.
- [x] Move runtime data under `memory/data/` for harness layout.

## Future Work
- [ ] Full local NVD mirror if zero-API dependency becomes required.
- [ ] User-defined remediation status history persistence.
