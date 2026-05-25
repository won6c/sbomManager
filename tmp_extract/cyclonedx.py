import json
from pathlib import Path
from typing import List, Any, Dict, Optional
from .requirements_spec import SBOMParser, Package, PURL, Ecosystem
from .spdx_parser import SPDXParser


class CycloneDXParser(SBOMParser):
    """
    CycloneDX JSON 포맷을 파싱하여 표준 Package 모델로 변환하는 구현체.
    """
    def parse(self, source: Path) -> List[Package]:
        with open(source, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # CycloneDX JSON 구조에서 components 리스트 추출
        components = data.get("components", [])
        # 1단계: 구성 요소 파싱 및 bom-ref 맵 생성
        package_map = self.sanitize(components)

        # 2단계: 상위 dependencies 리스트를 통해 의존성 매핑
        dependencies_list = data.get("dependencies", [])
        for dep in dependencies_list:
            ref = dep.get("ref")
            depends_on = dep.get("dependsOn")
            if ref in package_map and depends_on:
                # 내부 ID(bom-ref)를 실제 PURL로 변환하여 저장
                if depends_on in package_map:
                    package_map[ref].dependencies.add(str(package_map[depends_on].purl))
                else:
                    # 외부 의존성인 경우 IDs를 그대로 둠 (또는 추후 분석에서 처리)
                    package_map[ref].dependencies.add(depends_on)

        return list(package_map.values())

    def sanitize(self, raw_components: List[Dict[str, Any]]) -> Dict[str, Package]:
        """
        불완전한 데이터를 정제하고 PURL 표준으로 변환하여 bom-ref 맵으로 반환.
        """
        sanitized_packages = {}

        for comp in raw_components:
            try:
                # 1. 기본 정보 추출
                bom_ref = comp.get("bom-ref")
                if not bom_ref:
                    continue # bom-ref가 없으면 의존성 매핑이 불가능하므로 스킵

                name = comp.get("name")
                version = comp.get("version", "0.0.0")

                # 2. PURL 추출 및 생성
                # CycloneDX는 보통 'purl' 필드를 직접 제공함
                purl_str = comp.get("purl")
                purl = self._parse_purl(purl_str, name, version)

                if not name or not purl:
                    continue # 필수 정보 누락 시 스킵

                # 3. 의존성 추출
                deps = set()
                # 의존성은 이제 parse() 메서드에서 top-level dependencies 리스트를 통해 처리함

                # 4. 모델 생성
                pkg = Package(
                    purl=purl,
                    dependencies=deps,
                    path_on_disk=None # SBOM에는 보통 경로가 없으며, 이후 Binary Probe에서 매칭함
                )
                sanitized_packages[bom_ref] = pkg
            except Exception as e:
                # 개별 패키지 파싱 에러가 전체 프로세스를 중단시키지 않도록 함
                print(f"Error sanitizing component {comp.get('name')}: {e}")

        return sanitized_packages

    def _parse_purl(self, purl_str: Optional[str], name: Optional[str], version: str) -> Optional[PURL]:
        return super()._parse_purl(purl_str, name, version)
