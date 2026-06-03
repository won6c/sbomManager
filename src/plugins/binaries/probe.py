import os
import hashlib
import stat
from pathlib import Path
from typing import List, Dict, Any, Literal, Optional
from dataclasses import dataclass, asdict

from elftools.elf.elffile import ELFFile
from core.base import BasePlugin

@dataclass
class BinaryAsset:
    path: str
    sha256: str
    permissions: str
    is_setuid: bool
    is_setgid: bool
    mitigations: Dict[str, Any]
    privilege_level: Literal["ROOT", "USER", "PRIVILEGE_RESTRICTED"]

class BinaryProbePlugin(BasePlugin):
    @property
    def name(self) -> str:
        return "binary_probe"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def plugin_type(self) -> str:
        return "SYSTEM_PROBE"

    def validate_config(self, config: Dict[str, Any]) -> bool:
        return "scan_paths" in config and isinstance(config["scan_paths"], list)

    def _calculate_sha256(self, path: Path) -> str:
        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _analyze_elf(self, path: Path) -> Dict[str, Any]:
        mitigations = {"nx": False, "pie": False, "relro": "none"}
        
        with open(path, "rb") as f:
            elf = ELFFile(f)
            
            # PIE check: Check if type is shared object (ET_DSO) or if it has specific relocations
            if elf.header['e_type'] == 3: # ELF32/64 ET_DSO
                mitigations["pie"] = True
                
            # NX check: Look for GNU_STACK header
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_GNU_STACK':
                    # If the stack is not executable, NX is active
                    if not (segment['p_flags'] & 1): # PF_X is 1
                        mitigations["nx"] = True
            
            # RELRO check: Search for GNU_RELRO segment
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_GNU_RELRO':
                    mitigations["relro"] = "partial"
                    # Full RELRO usually involves BIND_NOW in dynamic section
                    # For this basic probe, we mark as partial if segment exists
                    # Full RELRO verification requires checking DT_FLAGS_SHT_BIND_NOW
            
            # Refine RELRO to 'full' if possible
            dyn = elf.get_section_by_name('.dynamic')
            if dyn:
                for entry in dyn.iter_entries():
                    if entry['d_tag'] == 15: # DT_FLAGS
                        if entry['d_val'] & 1: # DF_SHT_BIND_NOW
                            mitigations["relro"] = "full"
                            
        return mitigations

    def execute(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        scan_paths = config.get("scan_paths", [])
        results = []

        for path_str in scan_paths:
            root_path = Path(path_str)
            if not root_path.exists():
                continue

            for file_path in root_path.rglob("*"):
                if not file_path.is_file():
                    continue
                
                try:
                    # Check if ELF
                    with open(file_path, "rb") as f:
                        if f.read(4) != b"\x7fELF":
                            continue

                    st = file_path.stat()
                    mode = st.st_mode
                    
                    asset = BinaryAsset(
                        path=str(file_path.absolute()),
                        sha256=self._calculate_sha256(file_path),
                        permissions=stat.filemode(mode),
                        is_setuid=bool(mode & stat.S_ISUID),
                        is_setgid=bool(mode & stat.S_ISGID),
                        mitigations=self._analyze_elf(file_path),
                        privilege_level="ROOT" if st.st_uid == 0 else "USER"
                    )
                    results.append(asdict(asset))
                    
                except PermissionError:
                    # Log and record as restricted
                    results.append({
                        "path": str(file_path.absolute()),
                        "privilege_level": "PRIVILEGE_RESTRICTED",
                        "error": "Permission Denied"
                    })
                except Exception as e:
                    # Unexpected errors
                    continue

        return results
