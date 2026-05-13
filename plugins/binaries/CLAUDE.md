# Binary Probe - Exploit Surface Analyzer

## Responsibilities
- Path-limited binary discovery.
- ELF analysis: NX, PIE, RELRO, setuid/setgid.
- Hash generation (SHA-256).

## Requirements
- Use `pyelftools` for ELF parsing.
- Respect user-defined scope to prevent system lag.
- Handle `PRIVILEGE_RESTRICTED` for system-protected binaries.

## Tasks
- [ ] Define binary analysis data model.
- [ ] Implement recursive path scanner.
- [ ] Implement ELF mitigation checker.
- [ ] Integrate with Core Correlation Engine.
