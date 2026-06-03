# Data and Memory Session Log

## 2026-05-11: Initial CPE Cache
- Introduced cache-backed CPE/CVE lookups to reduce repeated external requests.
- Early CPE cache artifacts were stored under `data/` before the harness layout migration.

## 2026-05-25: SQLite Intelligence Cache
- Implemented SQLite-backed CVE cache for NVD responses.
- Added TTL-based cache validation to reduce NVD rate-limit pressure.
- Empty NVD results can be cached to avoid repeated no-op lookups.

## 2026-06-03: Scan History Persistence
- Added filesystem-backed scan history storage.
- Persisted scan summaries, scan detail payloads, and comparison deltas for demo/review workflows.

## 2026-06-03: Harness Layout Migration
- Runtime/local data moved from `data/` to `memory/data/`.
- `src/core/storage.py` default DB path is now `memory/data/intelligence_cache.db`.
- `src/core/scan_history.py` default root is now `memory/data/scan_history`.
- `.gitignore` excludes runtime cache outputs while preserving curated test cache fixtures.
