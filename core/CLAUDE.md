# Core Orchestration Engine

## Responsibilities
- Plugin lifecycle management (loading, unloading).
- Pipeline execution (Ingest -> Map -> Export).
- Base abstract classes for plugins.

## Detailed Collection Scope
The system must identify and track the following asset categories:
- **Kernel**: Version, Release, Build, Patch level, and security patches (Ksplice/Livepatch).
- **Software Packages**: (npm, pip, maven, etc.) $\rightarrow$ Name, Version, Ecosystem, Dependency Depth, License, Hash.
- **Binaries**: (ELF, PE, Mach-O) $\rightarrow$ SHA-256, Absolute Path, Permissions (rwx), setuid/setgid flags, Compiler flags (if detectable).
- **Daemons & Services**: (systemd, k8s) $\rightarrow$ Service name, bound Ports (TCP/UDP), User Context, Runtime status, PID.
- **3rd Party/Proprietary**: (Blobs, SDKs) $\rightarrow$ Vendor, Delivery Method, Verification signatures, Provenance.
- **Environment/Config**: OS Distribution, Hostname, Architecture (x86_64, ARM64), Environment Variables (security-relevant).

## Vulnerability Management Workflow
Instead of automated "Fixed in" strings, the system uses a user-defined status model:
- `Open` $\rightarrow$ `Handled` $\rightarrow$ `Mitigated` $\rightarrow$ `Delayed` $\rightarrow$ `False Positive` $\rightarrow$ `Ignored`.

## Tracking
- Progress: `progress.json`
- Session Log: `session_log.md`

## Tasks
- [ ] Implement `BasePlugin` abstract class.
- [ ] Implement `PluginManager` for dynamic loading.
- [ ] Implement `Pipeline` orchestrator.
- [ ] Define core data models for internal SBOM representation.
