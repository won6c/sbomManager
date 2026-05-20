import json
from pathlib import Path
from typing import List, Any, Dict, Optional
from .requirements_spec import SBOMParser, Package, PURL, Ecosystem

class SPDXParser(SBOMParser):
    """
    SPDX (Software Package Data Exchange) JSON 포맷을 파싱하여
    표준 Package 모델로 변환하는 구현체.
    """
    def parse(self, source: Path) -> List[Package]:
        with open(source, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # SPDX JSON에서는 'packages' 리스트에 정보가 포함됨
        packages_raw = data.get("packages", [])

        # 1단계: 기본 정보 정제 및 매핑
        package_map = self.sanitize(packages_raw)

        # 2단계: relationships 리스트를 통해 의존성 매핑
        relationships = data.get("relationships", [])
        for rel in relationships:
            if rel.get("relationship") == "DEPENDS_ON":
                first = rel.get("spdxId")
                second = rel.get("second")

                if first in package_map and second:
                    # 내부 ID(spdxId)를 실제 PURL로 변환하여 저장
                    if second in package_map:
                        package_map[first].dependencies.add(str(package_map[second].purl))
                    else:
                        package_map[first].dependencies.add(second)

        return list(package_map.values())

    def sanitize(self, raw_packages: List[Dict[str, Any]]) -> Dict[str, Package]:
        """
        SPDX 데이터를 정제하여 PURL 표준으로 변환하고 spdxId 맵으로 반환.
        """
        sanitized_packages = {}

        for pkg_data in raw_packages:
            try:
                # 1. 식별자 추출 (spdxId)
                spdx_id = pkg_data.get("spdxId")
                if not spdx_id:
                    continue

                name = pkg_data.get("name")
                version = pkg_data.get("versionInfo", "0.0.0")

                # 2. PURL 추출
                # SPDX는 'externalRefs' 내에 purl이 포함될 수 있음
                purl_str = None
                external_refs = pkg_data.get("externalRefs", [])
                for ref in external_refs:
                    if ref.get("type") == "purl":
                        purl_str = ref.get("value")
                        break

                purl = self._parse_purl(purl_str, name, version)

                if not name or not purl:
                    continue

                # 3. 모델 생성
                pkg = Package(
                    purl=purl,
                    dependencies=set(), # 의존성은 parse()에서 처리
                    path_on_disk=None
                )
                sanitized_packages[spdx_id] = pkg

            except Exception as e:
                print(f"Error sanitizing SPDX package {pkg_data.get('name')}: {e}")

        return sanitized_packages

    def _parse_purl(self, purl_str: Optional[str], name: Optional[str], version: str) -> Optional[PURL]:
        return super()._parse_purl(purl_str, name, version)
