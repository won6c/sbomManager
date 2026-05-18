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
