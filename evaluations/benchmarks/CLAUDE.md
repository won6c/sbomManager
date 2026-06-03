# Evaluation and Testing Framework

## Responsibilities
- Unit tests for core logic and plugin contracts.
- Integration tests for CPE/CVE, scan, risk, and persistence flows.
- Targeted verification scripts for probes and intelligence providers.
- Regression coverage for active TODO implementations.

## Layout
- `test_*.py`: pytest unit/integration tests.
- `verify_*.py`: targeted verification scripts for manual or CI-style checks.
- `integration_intelligence_test.py`: intelligence-chain integration coverage.
- `test_design.md`: testing design notes.

## Tracking
- Domain progress: `evaluations/benchmarks/progress.json`.
- Domain log: `evaluations/benchmarks/SESSION_LOG.md`.
- Root source of truth: `tasks/progress.json`.

## Completed Tasks
- [x] Setup pytest configuration through root `pytest.ini`.
- [x] Implement unit tests for `PluginManager`.
- [x] Implement integration tests for `Pipeline`.
- [x] Implement probe verification scripts.
- [x] Implement CPE/CVE flow tests.
- [x] Implement package probe, remediation, and scan history regression tests.
- [x] Move tests into harness layout under `evaluations/benchmarks/`.

## Current Verification Command

```bash
./scripts/verify.sh
```

Expected current result: 24 passed.
