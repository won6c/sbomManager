# Kernel Analysis Plugin

## Responsibilities
- Probe kernel version and build details.
- Analyze kernel configuration and security mitigations.
- Identify privilege escalation primitives.

## Technical Requirements
- Parse `/proc/version` and `/boot/config-*`.
- Check `/proc/config.gz` for `CONFIG_*` options.
- Evaluate KASLR, SMEP, SMAP states.

## Privilege Requirements
- **Root**: Full access to `/proc/config.gz` and `/boot/config-*`.
- **Non-Root**: Limited to `/proc/version`; other fields marked as `PRIVILEGE_RESTRICTED`.

## Tasks
- [ ] Implement `KernelProbe` for version detection.
- [ ] Implement `ConfigParser` for kernel config analysis.
- [ ] Implement mitigation state detection (KASLR, etc).
- [ ] Map kernel state to CVEs.
