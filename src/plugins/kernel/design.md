# Kernel Analysis Plugin Design

## User Story
**As a** security analyst, 
**I want to** automatically identify the kernel version and critical security configurations, 
**so that** I can determine if the system is vulnerable to known kernel-level exploits and evaluate the effectiveness of active kernel mitigations.

---

## 1. User Requirements
- The tool must identify the exact kernel version.
- The tool must identify if critical security features (like KASLR or SMEP) are enabled.
- The tool must not crash when run by a non-privileged user.
- The output must be concise and focused on security-relevant data, not thousands of generic kernel options.

## 2. System Requirements
- **Environment**: Linux-based systems (including WSL2).
- **Dependencies**: Python 3.10+, `platform` module.
- **Access**: Access to `/proc` and `/boot` directories.
- **Privilege Levels**: Support for both `root` (full access) and `non-root` (restricted access) execution.

## 3. Functional Requirements
- **Version Detection**: Extract kernel release information from the system.
- **Config Parsing**: 
    - Locate and parse `/proc/config.gz` and `/boot/config-*`.
    - Filter configurations using security-critical keywords: `KASLR`, `SMEP`, `SMAP`, `RWX`, `RANDOMIZE`, `STACK_PROTECTOR`, `HARDENED`.
    - **Method Choice**: Keyword-based filtering was chosen over a strict allow-list to balance noise reduction with coverage. Kernel configuration keys can vary slightly between versions; keyword matching ensures we capture all relevant security primitives (e.g., any variation of KASLR) without outputting thousands of irrelevant driver configs.
- **Privilege Mapping**: 
    - Detect current user's UID.
    - If `UID != 0`, mark inaccessible configuration data as `PRIVILEGE_RESTRICTED`.
- **Data Export**: Provide the results in a structured dictionary format for the Core Engine.

## 4. Non-Functional Requirements
- **Performance**: The probe must execute in under 1 second.
- **Stability**: Must handle missing files (e.g., `/proc/config.gz` not existing) without throwing unhandled exceptions.
- **Accuracy**: Configuration values must be extracted exactly as they appear in the source files.
- **Graceful Degradation**: The tool must remain functional and provide partial data even when root privileges are missing.

---

## Task Breakdown
- [x] Implement `KernelProbe` class structure.
- [x] Implement `get_version` for version detection.
- [x] Implement `get_config` with keyword-based filtering.
- [x] Implement root detection and `PRIVILEGE_RESTRICTED` markers.
- [x] Verify behavior with both `python3` and `sudo python3`.
