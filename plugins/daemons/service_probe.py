from .requirements_spec import SBOMParser, Package, PURL, Ecosystem
from .parsers.cyclonedx import CycloneDXParser
from .parsers.spdx import SPDXParser
from pathlib import Path
from typing import List, Any, Dict, Optional
from loguru import logger

class PackageAnalysisService:
    """
    SBOM 파싱부터 패키지 리스트 확보까지의 전체 흐름을 관리하는 서비스.
    """
    def __init__(self, parser_type: str = "cyclonedx"):
        if parser_type == "cyclonedx":
            self.parser = CycloneDXParser()
        elif parser_type == "spdx":
            self.parser = SPDXParser()
        else:
            raise NotImplementedError(f"Parser type {parser_type} is not supported yet.")

    def get_packages_from_sbom(self, sbom_path: str, base_dir: Optional[str] = None) -> List[Package]:
        """
        SBOM 파일 경로를 받아 정제된 패키지 리스트를 반환.
        base_dir가 제공되면 해당 경로 내의 파일만 허용하여 path traversal을 방지함.
        """
        try:
            path = Path(sbom_path).resolve(strict=True)

            if base_dir:
                base_path = Path(base_dir).resolve()
                if not str(path).startswith(str(base_path)):
                    raise PermissionError(f"Access denied: path {path} is outside base directory {base_path}")

            # 파일 크기 제한 (DoS 방지: 예: 50MB)
            if path.stat().st_size > 50 * 1024 * 1024:
                raise ValueError(f"SBOM file too large: {path.stat().st_size} bytes")

            # 1단계: 파싱 및 정제 수행
            packages = self.parser.parse(path)

            # 로깅: 몇 개의 패키지가 성공적으로 정제되었는지 기록
            logger.info(f"Successfully parsed and sanitized {len(packages)} packages from {sbom_path}")

            return packages
        except Exception as e:
            logger.error(f"Error processing SBOM file {sbom_path}: {e}")
            raise
