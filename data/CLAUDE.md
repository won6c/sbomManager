# Data Persistence Layer

## Responsibilities
- Storage of processed SBOMs, CVE maps, and System Assets.
- Schema management for:
    - Components (incl. Path, Mode bits, Ports).
    - Kernel (Version, Build, Patch level).
    - Vulnerabilities & MappingResults.
- Implementation of Status History for user-defined remediation.
- Cache implementation for external API results.

## Tracking
- Progress: `progress.json`
- Session Log: `session_log.md`

## Tasks
- [ ] Select database (SQLite/Postgres/etc).
- [ ] Define expanded SBOM and Vulnerability schemas (incl. Kernel, Ports, Permissions).
- [ ] Implement data access objects (DAOs).
- [ ] Implement Status History tracking table.
- [ ] Setup migration scripts.
