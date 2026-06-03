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

## Tasks
- [ ] Implement multi-format SBOM parser.
- [ ] Implement transitive dependency graph builder.
- [ ] Integrate CVE provider APIs.
- [ ] Implement runtime usage check (via `/proc/[pid]/maps`).
