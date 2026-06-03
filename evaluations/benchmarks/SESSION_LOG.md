# Evaluations Session Log

## 2026-05-05: Probe Verification
- Added targeted verification for `KernelProbe` and `DaemonProbe`.
- Verified graceful degradation for non-root environments and restricted `/proc`/system metadata.

## 2026-05-11: CPE/CVE Flow Tests
- Added end-to-end tests for Version -> CPE -> CVE mapping.
- Verified CPE resolver and CVE provider integration with caching/retry behavior.

## 2026-05-20: Risk and CVSS Tests
- Added CVSS extraction checks for NVD v2.0 responses.
- Added risk score verification scripts for TARA-style Impact x Feasibility scoring.

## 2026-05-25: Intelligence Feature Verification
- Added checks for reachability analysis, OSV integration, SBOM parsing, and NVD cache behavior.
- Network-dependent OSV checks are documented as environment-sensitive.

## 2026-05-27: Web/API Smoke Verification
- Verified backend compile, selected pytest suite, API health, CPE resolution, SBOM parsing, and scan smoke requests.
- Frontend lint/build passed in the web workspace.

## 2026-06-03: Active TODO Test Coverage
- Added tests for PackageProbe, RemediationEngine, and ScanHistoryStore.
- Confirmed package probe and scan-history API smoke checks.

## 2026-06-03: Harness Layout Migration
- Test suite moved from `tests/` to `evaluations/benchmarks/`.
- Added `pytest.ini` with `testpaths = evaluations/benchmarks` and `pythonpath = src`.
- Fixed `test_full_flow.py` missing `sys` import surfaced during full-suite execution.
- Final verification: `./scripts/verify.sh` passed with 24 tests.
