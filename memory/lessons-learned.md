# Lessons Learned

## Probe Scope
- Keep binary scanning path-limited. Full host scans can create lag and noisy findings.
- Treat non-root probe gaps as explicit `PRIVILEGE_RESTRICTED` evidence instead of failing the full scan.

## Intelligence
- NVD and OSV calls are network/rate-limit dependent. Use SQLite/file cache under `memory/data/` to reduce repeated requests.
- CPE resolution should support fallback only when there is concrete name/version evidence; avoid generating confident CPEs for unknown services.

## Risk Scoring
- Raw CVE count is not enough. Prioritize Impact x Feasibility using CVSS, exposure, privilege, reachability, exploit evidence, and mitigations.
- Loaded-in-memory reachability is a strong feasibility signal.

## Repository Operation
- `tasks/progress.json` is the source of truth; domain `progress.json` files are mirrors/summaries.
- Old unchecked checklist items in domain `CLAUDE.md` files can be stale. Reconcile them against code/tests before treating them as active work.
- After harness layout migration, commands should run with `PYTHONPATH=$PWD/src` or through `scripts/*.sh`.
