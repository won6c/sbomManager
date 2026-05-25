import os
import psutil
from pathlib import Path
from typing import List, Tuple, Dict, Set
from ..requirements_spec import ReachabilityAnalyzer, Package
from loguru import logger

class ProcMapsReachabilityAnalyzer(ReachabilityAnalyzer):
    """
    /proc/[pid]/maps 분석을 통해 패키지 파일이 실제 메모리에 로드되었는지 검증하는 구현체.
    성능 최적화를 위해 모든 프로세스의 메모리 맵을 한 번만 스캔하여 캐싱합니다.
    """
    def __init__(self):
        # _global_maps_cache: { "path/to/lib": { (addr_range, perms), ... } }
        self._global_maps_cache: Dict[str, Set[Tuple[str, str]]] = {}
        self._cache_valid = False

    def _refresh_cache(self):
        """
        시스템의 모든 프로세스를 순회하며 로드된 모든 라이브러리 경로와 메모리 영역을 캐싱합니다.
        O(P) 복잡도로 한 번만 수행됩니다.
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
                            # maps 라인 포맷: 7f3a2b000-7f3a2c000 r-xp 00000000 00:00 0 /usr/lib/libssl.so.1.1
                            parts = line.split()
                            if len(parts) >= 6:
                                addr_range = parts[0]
                                perms = parts[1]
                                path = parts[5]

                                # 경로가 유효한 경우에만 캐싱
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

    def check_memory_load(self, package: Package) -> Tuple[bool, List[Tuple[str, str]]]:
        """
        캐싱된 메모리 맵을 사용하여 패키지가 로드되었는지 확인합니다.
        O(1) lookup으로 성능이 극대화됩니다.
        """
        if not package.path_on_disk:
            logger.debug(f"Package {package.purl} has no path_on_disk; skipping memory load check.")
            return False, []

        if not self._cache_valid:
            self._refresh_cache()

        target_path = str(package.path_on_disk.resolve())

        # 캐시에서 직접 조회
        regions = self._global_maps_cache.get(target_path, set())

        return len(regions) > 0, list(regions)

    def verify_symbol_existence(self, vuln_functions: List[str], memory_regions: List[Tuple[str, str]]) -> List[str]:
        """
        메모리 영역 내에 실제 취약 함수 심볼이 존재하는지 검증.
        """
        if not vuln_functions:
            return []

        # 실행 권한(x)이 있는 메모리 영역이 하나라도 있는지 확인
        has_executable_region = any('x' in perms for _, perms in memory_regions)

        if not has_executable_region:
            return []

        # 실제 심볼 분석은 ELF 분석 도구 연동이 필요함.
        # 현재는 실행 가능 영역에 매핑되어 있다면 잠재적 위험으로 간주하여 반환.
        return vuln_functions
