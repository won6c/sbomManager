---
name: sbom-manager-analysis
description: Use when developing SBOM Manager features that correlate probes, CVE/OSV intelligence, reachability, and TARA risk scoring.
version: 1.0.0
author: SBOM Manager Team
license: MIT
metadata:
  hermes:
    tags: [sbom, vulnerability, tara, reachability, probes]
    related_skills: []
---

# SBOM Manager Analysis

## Overview
SBOM Manager turns passive component inventory into exploit surface analysis. The central workflow is:

Discovery -> Enrichment -> Intelligence -> Reachability -> TARA Risk -> Remediation

## When to Use
- Adding or changing Kernel, Binary, Package, Daemon, or 3rd-party probes.
- Mapping assets to CPE/PURL/CVE/OSV intelligence.
- Updating risk scoring, reachability, or remediation logic.
- Preparing technical documentation for the SBOM Manager architecture.

## Workflow
1. Discover assets with bounded probes.
2. Normalize into Pydantic models.
3. Resolve package identity through package-manager metadata before heuristic matching.
4. Query NVD/OSV with persistent caching where possible.
5. Check runtime reachability through `/proc/[pid]/maps` for loaded binaries/libraries.
6. Score risk with TARA: Impact x Feasibility.
7. Produce remediation recommendations tied to evidence.

## Pitfalls
- Do not scan arbitrary filesystem paths without user-defined scope.
- Do not treat CVE existence as exploitability; consider exposure, privilege, mitigations, and reachability.
- Do not trust old unchecked TODOs without reconciling them against root `tasks/progress.json` and current code.

## Verification Checklist
- [ ] Unit tests cover new model/logic behavior.
- [ ] API smoke test returns JSON-serializable output.
- [ ] `python -m py_compile` passes for changed Python files.
- [ ] `tasks/done/SESSION_LOG.md` and `tasks/progress.json` are updated.
