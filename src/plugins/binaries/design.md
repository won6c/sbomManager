# Binary Probe Design Specification

## 1. Objective
Extract security-critical metadata from ELF binaries within specified paths to identify exploitability markers (e.g., missing NX/PIE) and potential privilege escalation vectors (setuid).

## 2. Analysis Pipeline
1. **Discovery**: Recursive walk of user-provided `scan_paths`.
2. **Filtering**: Ignore non-ELF files (magic byte check) and symlinks.
3. **ELF Parsing**:
    - **Header Analysis**: Check for PIE (Position Independent Executable).
    - **Program Headers**: Verify NX (No-Execute) by checking for executable stacks.
    - **Dynamic Section**: Verify RELRO (Relocation Read-Only) status.
4. **System Metadata**:
    - **Permissions**: Check for setuid/setgid bits.
    - **Identity**: Calculate SHA-256 hash.
    - **Ownership**: Resolve UID/GID.

## 3. Data Model (Pydantic)
```python
class BinaryAsset(BaseModel):
    path: Path
    sha256: str
    permissions: str
    is_setuid: bool
    is_setgid: bool
    elf_mitigations: {
        "nx": bool,
        "pie": bool,
        "relro": Literal["none", "partial", "full"]
    }
    privilege_level: Literal["ROOT", "USER", "PRIVILEGE_RESTRICTED"]
```

## 4. Performance Constraints
- **Path Limiting**: Limit depth and total file count to prevent OOM/CPU spikes.
- **Lazy Loading**: Only read the ELF header/program headers; avoid reading the entire binary.

## 5. Error Handling
- `PermissionError` $\rightarrow$ Mark as `PRIVILEGE_RESTRICTED`.
- `InvalidELF` $\rightarrow$ Log and skip.
