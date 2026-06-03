# Architecture

## Harness Flow

```text
Frontend/API request -> src/main.py -> SystemCollector -> scoped probes -> intelligence enrichment -> reachability -> TARA risk/remediation -> persistence/reporting
```

## Runtime Layers

| Layer | Path | Role |
|---|---|---|
| API | `src/main.py`, `src/api/` | Exposes scan and intelligence endpoints. |
| Core harness | `src/core/collector.py`, `src/core/pipeline.py`, `src/core/plugin_manager.py` | Orchestrates probes, enrichment, scoring, remediation, and persistence. |
| Probes | `src/plugins/` | Kernel, binary, daemon, package, SBOM, and intelligence plugins. |
| Evaluations | `evaluations/benchmarks/` | Unit, integration, and verification tests. |
| Memory/data | `memory/data/` | Local cache, scan history, and curated test fixtures. |
| Reports | `evaluations/reports/` | Presentation and evaluation artifacts. |

## Key Design Principles
- Correlation over collection.
- Exploitability and reachability over raw CVE counts.
- User-scoped binary scanning.
- Graceful degradation for non-root execution.
