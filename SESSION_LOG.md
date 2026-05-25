# Session Log - SBOM Manager

Session 1
Architecture Finalized: All CLAUDE.md files synchronized with risk-aware asset scope (Kernel, Binaries, Daemons, 3P, Ports, Permissions) and user-driven status workflow. Tech stack approved. Core module implemented and validated. Project ready for Plugin/Data layer execution.

### 2026-05-05 14:22 - Daemon Probe Implementation
- Implemented DaemonProbe with hybrid systemd/psutil approach.
- Added robust binary path resolution to avoid garbage characters (e.g., '{').
- Implemented non-root graceful degradation with PRIVILEGE_RESTRICTED markers.
- Verified with tests/verify_daemons.py (Passed).
- Handled environment where psutil returns PID=None for sockets.

### 2026-05-05 14:24 - Kernel Probe Implementation
- Implemented KernelProbe for version detection and security config extraction.
- Implemented keyword-based filtering (KASLR, SMEP, SMAP, etc.) to reduce noise.
- Implemented non-root graceful degradation with PRIVILEGE_RESTRICTED markers.
- Verified with tests/verify_kernel.py (Passed).
- Handled missing /proc/config.gz and /boot/config- files gracefully.

### 2026-05-11: Version -> CPE -> CVE Flow Implementation
- **Goal**: Automate the mapping from software versions to CVEs using external intelligence.
- **Key Achievements**:
    - Designed and implemented `CPEResolverPlugin` to bridge Version -> CPE.
    - Integrated Shodan and Metasploit APIs for real-world CPE resolution.
    - Implemented a file-based cache with 30-day TTL in `data/cpe_cache/`.
    - Enhanced `core/pipeline.py` to execute CPE resolution during the `ENRICH` stage.
    - Added robust HTTP retry logic (handling 429 Rate Limits) using `requests` and `urllib3`.
    - Verified the end-to-end flow via integration tests (`tests/test_cpe_cve_flow.py`).
    - Secured API key management using `.env`.

## 2026-05-13: Core Orchestration and API Infrastructure Implementation

### 1. Daemon Probe Optimization
- Implemented port-based deduplication in `plugins/daemons/probe.py`.
- Added logic to prioritize more informative entries (version > description > path) when multiple entries exist for the same port.

### 2. Core Orchestration Layer
- Created `core/collector.py`: Implemented `SystemCollector` for asynchronous coordination of Kernel, Daemon, and Binary probes using `asyncio` and `ThreadPoolExecutor`.
- Standardized data models in `core/models.py` using Pydantic for consistent JSON serialization and type safety.

### 3. API Layer (FastAPI)
- Implemented `main.py`: Provided `/scan` and `/health` endpoints.
- Integrated `SystemCollector` to allow dynamic binary scan path injection via API requests.
- Verified End-to-End flow: 웹 요청 -> Core 수집 -> JSON 응답.

### 4. Intelligence Layer Restructuring
- Moved CPE, NVD, and Metasploit plugins to `plugins/intelligence/` for better modularity.
- Patched import statements across the codebase to support the new structure.
- Refined `CPEResolverPlugin` to prevent aggressive auto-generation of CPEs for "unknown" services.

### 5. Project Cleanup
- Migrated temporary test scripts (e.g., `interactive_analyzer.py`, `test_full_flow.py`) to the `tests/` directory.

---

## 2026-05-18: Integration of Intelligence Chain
- **Objective**: Connect Asset Discovery to CVE mapping.
- **Key Accomplishments**:
    - Integrated `CPEResolverPlugin` and `CVEProviderPlugin` into `core/collector.py`.
    - Fixed `CPEResolver` to generate synthetic CPEs when valid Name/Version are present, enabling CVE lookups even without API matches.
    - Implemented NVD API v2.0 provider for automated CVE retrieval.
    - Verified E2E flow: `Sytem Scan` -> `CPE Resolution` -> `CVE Mapping`.
    - Confirmed real-world matches for PostgreSQL and MySQL services.
- **Issues Resolved**:
    - Fixed `AttributeError` in `DaemonAsset` by restoring `description` field.
    - Resolved `ValueError` regarding missing `cpe` field in Asset models.
- **Next Milestone**: Fix FastAPI JSON serialization error and implement Package Probe.

## 2026-05-20: API Stabilization and TARA Risk Scoring Implementation
- **API Fix**: Resolved `maximum recursion depth exceeded` error in `/scan` endpoint by replacing `model_dump()` with `jsonable_encoder` and explicitly typing `Vulnerability` lists in Pydantic models.
- **CVSS Intelligence**: Updated `CVEProviderPlugin` to extract precise CVSS v3.1/3.0/2.0 base scores from NVD API v2.0, moving beyond simple severity labels.
- **Risk Engine Implementation**:
    - Designed and implemented `core/risk_engine.py` using a TARA-based methodology ($\text{Impact} \times \text{Feasibility}$).
    - **Impact Logic**: Automation based on `PrivilegeLevel` (Root vs User) and max `CVSS Score`.
    - **Feasibility Logic**: Calculation based on `Exposure` (External vs Internal), `Mitigations` (NX, PIE, RELRO), and existence ofKNOWN exploits.
- **Pipeline Integration**: Integrated the Risk Engine into `SystemCollector.collect()`, enabling end-to-end flow: $\text{Discovery} \rightarrow \text{CPE} \rightarrow \text{CVE} \rightarrow \text{Risk Score}$.
- **Verification**: Validated the full pipeline via API, confirming correct risk scores (e.g., Critical/High) for vulnerable external services in the JSON output.

## 2026-05-25: Infra Optimization and Reachability-Aware Intelligence Integration
- **Infra Optimization (SQLite Cache)**:
    - Implemented `CVEStorage` using SQLite to replace flat-file JSON cache.
    - Achieved high-performance vulnerability lookups and mitigated NVD API rate limits.
- **Intelligence Feature Expansion (from packages_dev branch)**:
    - **Reachability Analysis**: Integrated `/proc/[pid]/maps` analysis to detect if a binary/library is actually loaded in memory.
    - **OSV Integration**: Added `OSVCVEProvider` to complement NVD with open-source specific vulnerability data.
    - **SBOM Parsing**: Implemented `CycloneDXParser` to allow ingestion of standard SBOM files.
- **API Granularization**:
    - Decomposed the monolithic `/scan` endpoint into specialized intelligence APIs: `/intelligence/cpe`, `/intelligence/cve`, `/intelligence/osv`, `/intelligence/reachability`, and `/intelligence/sbom/parse`.
- **Full Pipeline Integration**:
    - Updated `SystemCollector` to a "Reachability-Aware" flow: `Discovery` $\rightarrow$ `Reachability Check` $\rightarrow$ `NVD/OSV Ensemble` $\rightarrow$ `TARA Risk Scoring`.
    - Risk scoring now treats "Loaded in Memory" as a critical feasibility multiplier.
- **Validation**: Verified all new features via `tests/verify_new_features.py` and live API requests.

### Pending ToDo:
- [ ] Implement Package Probe for high-precision versioning.
- [ la l] Build Risk Visualizer dashboard for prioritized mitigation.
- [ ] Implement risk-based remediation guidance module.
- [ ] Full NVD Mirroring for zero-API dependency.


## 2026-05-25: NVD API Caching Implementation
- **Goal**: Mitigate NVD API rate limiting and reduce latency for repeated CVE lookups.
- **Key Accomplishments**:
    - Implemented `CVECache` class providing file-based storage in `data/nvd_cache/`.
    - Integrated cache logic into `NvdCveProviderPlugin` (Cache Check $\rightarrow$ API Call $\rightarrow$ Update).
    - Set 7-day TTL for vulnerability data to balance freshness and performance.
    - Handled empty results (404) by caching them to prevent repeated useless API calls.
- **Verification**: Developed `tests/verify_nvd_cache.py` and verified request duration dropped from ~5.6s to ~0.03s on cache hit.

