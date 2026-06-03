# Architecture Decisions

## ADR-001: Harness Engineering Repository Layout
- Decision: organize the repo around harness execution artifacts: `src/`, `docs/`, `skills/`, `plans/`, `tasks/`, `scripts/`, `evaluations/`, and `memory/`.
- Reason: makes agent/human execution state explicit and separates runnable code from evaluations, plans, reports, and persistent project context.

## ADR-002: Path-Limited Binary Scanning
- Decision: binary probes must scan only user-provided paths.
- Reason: full filesystem binary scanning can lag or overload a host and creates unnecessary security noise.

## ADR-003: Graceful Degradation
- Decision: restricted probe results should be represented as explicit restricted evidence, not as full scan failure.
- Reason: the tool must remain useful for non-root users and demo environments.

## ADR-004: Exploitability-Weighted Risk
- Decision: prioritize TARA-style Impact x Feasibility using CVSS, exposure, reachability, exploit evidence, and binary mitigations.
- Reason: raw CVE count does not represent real attack surface.

## ADR-005: Local Cache Under `memory/data/`
- Decision: runtime intelligence cache and scan history live under `memory/data/`.
- Reason: aligns with harness memory semantics while keeping generated data separable from source code and curated fixtures.
