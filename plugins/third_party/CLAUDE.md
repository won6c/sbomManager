# Third-Party Component Analysis Plugin

## Responsibilities
- Identify proprietary binaries and SDKs.
- Verify provenance and integrity.
- Flag unmanaged assets (no SBOM coverage).

## Technical Requirements
- Identify binaries via vendor signatures or hash databases.
- Scan non-standard paths (e.g., `/opt`, `/usr/local`).
- Implement signature and integrity verification.
- Track installation sources (provenance).

## Privilege Requirements
- **Root**: Ability to read all binaries in restricted paths.
- **Non-Root**: Limited to directories with user read permissions.

## Tasks
- [ ] Implement signature-based identification.
- [ ] Implement non-standard path scanner.
- [ ] Implement integrity verification logic.
- [ ] Implement provenance tracking.
