import asyncio
import aiohttp
from typing import List, Optional
from ..requirements_spec import CVEProvider, PURL, Vulnerability
from loguru import logger

class OSVCVEProvider(CVEProvider):
    """
    OSV (Open Source Vulnerabilities) API를 이용한 취약점 조회 구현체.
    """
    OSV_API_URL = "https://api.osv.dev/v1/query"

    async def fetch_vulnerabilities(self, purl: PURL) -> List[Vulnerability]:
        """
        PURL을 기반으로 OSV API에서 취약점 목록을 비동기적으로 조회.
        """
        purl_str = str(purl)
        payload = {"package": {"purl": purl_str}}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.OSV_API_URL, json=payload) as response:
                    if response.status != 200:
                        logger.error(f"OSV API error: {response.status} for {purl_str}")
                        return []

                    data = await response.json()
                    vulns_data = data.get("vulns", [])

                    return self._map_osv_to_model(vulns_data)
        except Exception as e:
            logger.exception(f"Failed to fetch vulnerabilities from OSV for {purl_str}: {e}")
            return []

    def _map_osv_to_model(self, vulns_data: List[dict]) -> List[Vulnerability]:
        """
        OSV API 응답 형식을 내부 Vulnerability 모델로 변환.
        """
        results = []
        for v in vulns_data:
            cve_id = v.get("id", "UNKNOWN")

            # CVSS 점수 추출 (OSV는 여러 포맷으로 제공하므로 최선을 다해 추출)
            cvss_score = 0.0
            for severity in v.get("severity", []):
                if "score" in severity:
                    try:
                        cvss_score = float(severity["score"])
                        break
                    except (ValueError, TypeError):
                        continue

            # 영향 받는 버전 범위 추출
            affected_ranges = []
            for affected in v.get("affected", []):
                # OSV의 ranges 필드는 특수한 문법을 사용함
                events = affected.get("ranges", [])
                for event in events:
                    type_ = event.get("type")
                    value = event.get("value")
                    if type_ and value:
                        affected_ranges.append(f"{type_}: {value}")

            # 취약 함수/심볼 추출 (OSV에서는 직접적으로 제공하지 않는 경우가 많아 빈 리스트로 시작)
            # 추후 상세 분석 데이터를 추가하여 보완 가능
            vuln_functions = []

            # Fix 버전 추출
            fixed_in = None
            for affected in v.get("affected", []):
                for event in affected.get("ranges", []):
                    if event.get("type") == "fixed":
                        fixed_in = event.get("value")
                        break

            results.append(Vulnerability(
                cve_id=cve_id,
                cvss_score=cvss_score,
                affected_version_ranges=affected_ranges,
                vulnerable_functions=vuln_functions,
                fixed_in=fixed_in
            ))

        return results
