# Package Analysis Plugin

## Responsibilities
- Parse SBOM formats (CycloneDX, SPDX) and manifest files.
- Build transitive dependency graphs.
- Map packages and versions to vulnerability databases.

## Technical Requirements
- Support for CycloneDX and SPDX parsing.
- Integration with OSV, NVD, and GitHub Advisory APIs.
- Logic to detect "abandoned" or outdated packages.
- Runtime reachability analysis (mapping used libs to vulnerabilities).

## Privilege Requirements
- **Root**: Access to system package manager databases (dpkg, rpm).
- **Non-Root**: Limited to provided SBOM files or user-level package manifests.

## Implementation Status
- [x] Implement multi-format SBOM parser (CycloneDX, SPDX).
- [x] Implement transitive dependency graph builder (via networkx).
- [x] Integrate CVE provider APIs (OSV implemented).
- [x] Implement runtime usage check (via /proc/[pid]/maps).
- [x] Implement Risk Scoring engine.
- [x] Modularize project structure into parsers, analysis, and providers.

## Architecture
- **Parsers**: `parsers/cyclonedx.py`, `parsers/spdx.py`
- **Analysis**: `analysis/graph.py` (Dependency Graph), `analysis/reachability.py` (Runtime check), `analysis/scorer.py` (Risk Score)
- **Providers**: `providers/osv.py` (Vulnerability data)
- **Service**: `service.py` (Orchestration)
- **Specs**: `requirements_spec.py` (Interface definitions)
