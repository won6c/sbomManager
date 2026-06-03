import os
import psutil
from pathlib import Path
from typing import List, Tuple, Dict, Set
from loguru import logger

class ProcMapsReachabilityAnalyzer:
    """
    Analyzes /proc/[pid]/maps to verify if a binary or library is actually loaded in memory.
    This provides a critical 'reachability' signal for risk scoring.
    """
    def __init__(self):
        # _global_maps_cache: { "path/to/lib": { (addr_range, perms), ... } }
        self._global_maps_cache: Dict[str, Set[Tuple[str, str]]] = {}
        self._cache_valid = False

    def _refresh_cache(self):
        """
        Scans all running processes and caches all loaded libraries and memory regions.
        Complexity: O(P) where P is number of processes.
        """
        logger.debug("Refreshing global memory maps cache...")
        self._global_maps_cache.clear()

        try:
            for proc in psutil.process_iter(['pid']):
                pid = proc.info['pid']
                try:
                    maps_path = Path(f"/proc/{pid}/maps")
                    if not maps_path.exists():
                        continue

                    with open(maps_path, 'r') as f:
                        for line in f:
                            parts = line.split()
                            if len(parts) >= 6:
                                addr_range = parts[0]
                                perms = parts[1]
                                path = parts[5]

                                if path.startswith('/'):
                                    if path not in self._global_maps_cache:
                                        self._global_maps_cache[path] = set()
                                    self._global_maps_cache[path].add((addr_range, perms))
                except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
                    continue
                except Exception as e:
                    logger.trace(f"Error reading maps for PID {pid}: {e}")
                    continue
            self._cache_valid = True
        except Exception as e:
            logger.error(f"Global memory map cache refresh failed: {e}")
            self._cache_valid = False

    def check_memory_load(self, path: str) -> Tuple[bool, List[Tuple[str, str]]]:
        """
        Checks if the given path is loaded in any process's memory.
        """
        if not path:
            return False, []

        if not self._cache_valid:
            self._refresh_cache()

        try:
            target_path = str(Path(path).resolve())
            regions = self._global_maps_cache.get(target_path, set())
            return len(regions) > 0, list(regions)
        except Exception:
            return False, []

    def verify_executable_region(self, memory_regions: List[Tuple[str, str]]) -> bool:
        """
        Verifies if any of the loaded memory regions have execute (x) permissions.
        """
        return any('x' in perms for _, perms in memory_regions)
