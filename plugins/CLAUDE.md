# Pluggable Implementation Layer

## Responsibilities
- SBOM Parsers (CycloneDX, SPDX, etc.) and Asset Discoverers.
- CVE Providers (NVD, OSV, etc.).
- System probes for Kernel version, Binaries, and Running Daemons.

## Collection Requirements
Plugins must support the extended asset scope:
- **Kernel**: Version, Release, Build, and critical security patches (Ksplice/Livepatch).
- **Packages**: Ecosystem, Version, Dependency Depth, License.
- **Binaries**: SHA-256, Absolute Path, Permissions (rwx/setuid).
- **Daemons**: Service name, bound Ports, User Context, Runtime status.
- **3rd Party**: Vendor, Provenance, Verification signatures.

## Tracking
- Progress: `progress.json`
- Session Log: `session_log.md`

## Tasks
- [ ] Implement Mock SBOM Parser.
- [ ] Implement Mock CVE Provider.
- [ ] Implement Kernel version and build probe.
- [ ] Implement Binary/Daemon discovery plugin.
- [ ] Implement CycloneDX Parser.
- [ ] Implement NVD API Provider.
