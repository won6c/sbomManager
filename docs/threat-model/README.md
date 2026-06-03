# Threat Model

## Security Question
Which discovered host assets create realistic, reachable attack paths when package vulnerability, binary mitigation, daemon exposure, privilege, and runtime reachability evidence are correlated?

## Asset Categories
- Kernel: version, config, KASLR/SMEP/SMAP and related mitigations.
- Binaries: scoped ELF discovery, NX/PIE/RELRO, setuid/setgid, permissions, hashes.
- Packages: package-manager metadata, exact versions, PURL/CPE mapping, OSV/NVD vulnerabilities.
- Daemons: port -> PID -> binary mapping, listening address, service identity, user context.
- Third-party/proprietary components: vendor/provenance evidence where available.

## Risk Model

```text
Base Score (max CVSS) -> Exposure Multiplier -> Mitigation Factor -> TARA-style risk
```

- Impact: CVSS, privilege level, asset criticality.
- Feasibility: external exposure, loaded-in-memory reachability, exploit evidence, missing mitigations.
- Result: prioritized remediation and attack-path insight rather than passive SBOM inventory.
