# API Layer (FastAPI)

## Responsibilities
- Expose orchestration triggers.
- Serve mapped SBOM data to frontend.
- Support advanced filtering by Asset Category (Kernel, Package, Binary, Daemon, 3P), Status, and Network Port.
- Manage API authentication and rate limiting.

## Tracking
- Progress: `progress.json`
- Session Log: `session_log.md`

## Tasks
- [ ] Setup FastAPI basic structure.
- [ ] Implement `/trigger/pipeline` endpoint.
- [ ] Implement `/results/{id}` endpoint.
- [ ] Implement advanced filtering (Category, Port, Status, Severity).
- [ ] Implement status update endpoint for user-defined remediation.
