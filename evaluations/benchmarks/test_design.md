# Exploit Surface Analyzer - Design Specification

## Vision
Transform a passive SBOM manager into an active "Exploit Surface Analyzer" that correlates assets to identify real attack paths.

## Core Architecture: The Correlation Graph
The system no longer treats assets as lists, but as nodes in a directed graph:
`External Network` $\rightarrow$ `Listening Port` $\rightarrow$ `Daemon/Service` $\rightarrow$ `Binary` $\rightarrow$ `Package` $\rightarrow$ `Vulnerability`

## Feature Specifications

### 1. Kernel Analysis (plugins/kernel)
- **Data Collection**: Parse `/proc/version`, `/boot/config-*`, and `/proc/config.gz`.
- **Security Analysis**: 
    - Detect mitigation states: KASLR, SMEP, SMAP, seccomp.
    - Identify critical config options (e.g., `CONFIG_USER_NS`).
    - Check `/proc/kallsyms` exposure.
- **Risk**: Map version + config $\rightarrow$ Privilege Escalation CVEs.

### 2. Binary Analysis (plugins/binaries)
- **Data Collection**: ELF/PE/Mach-O header analysis.
- **Security Analysis**: 
    - Detect Mitigations: NX (No-Execute), PIE (Position Independent Executable), RELRO, Stack Canaries.
    - Inspect RPATH/RUNPATH for unsafe library loading.
    - Analyze setuid/setgid bits and file capabilities.
- **Risk**: Map binary $\rightarrow$ originating package $\rightarrow$ CVE.

### 3. Package Analysis (plugins/packages)
- **Data Collection**: Support CycloneDX and SPDX formats.
- **Security Analysis**:
    - Build full transitive dependency graphs.
    - Integrate OSV, NVD, and GitHub Advisory databases.
    - Identify "abandoned" or outdated packages.
- **Risk**: Determine if vulnerable dependencies are actually reachable at runtime.

### 4. Daemon & Service Analysis (plugins/daemons)
- **Data Collection**: Map listening ports to PIDs using `psutil` and `/proc/net`.
- **Security Analysis**:
    - Identify external exposure (0.0.0.0 vs 127.0.0.1).
    - Determine privilege context (root vs low-privilege).
    - Detect persistence (systemd enabled).
- **Risk**: Map service $\rightarrow$ binary $\rightarrow$ package $\rightarrow$ CVE.

### 5. Third-Party Analysis (plugins/third_party)
- **Data Collection**: Scan `/opt`, `/usr/local` and identify via vendor signatures/hashes.
- **Security Analysis**:
    - Verify signatures and integrity.
    - Track provenance (source of installation).
- **Risk**: Flag unmanaged binaries with no SBOM coverage.

### 6. Relation Graph (core/graph)
- **Implementation**: Use a graph data model to link the above probes.
- **Insight Generation**: Identify "Attack Paths" (e.g., "Externally exposed root service running vulnerable binary").

## Privilege Handling (Root Exception)
The system must implement a **Graceful Degradation** model for non-root users:
- **Detection**: Check `os.geteuid() == 0` at startup.
- **Behavior**: 
    - If not root: Skip protected probes (e.g., certain `/proc` files, some binary capabilities).
    - **Reporting**: Mark these data points as `UNKNOWN` or `PRIVILEGE_RESTRICTED`.
    - **Notification**: Add a warning to the final report: "Some analysis was limited due to insufficient privileges. Run as root for full exploit surface visibility."
