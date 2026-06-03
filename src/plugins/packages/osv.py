import asyncio
import aiohttp
from typing import List, Optional, Dict, Any
from loguru import logger

class OSVCVEProvider:
    """
    OSV (Open Source Vulnerabilities) API Provider.
    Provides vulnerability data for open-source packages using PURL.
    """
    OSV_API_URL = "https://api.osv.dev/v1/query"

    async def fetch_vulnerabilities(self, purl: str) -> List[Dict[str, Any]]:
        """
        Query OSV API for vulnerabilities matching the given PURL.
        """
        if not purl:
            return []

        payload = {"package": {"purl": purl}}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.OSV_API_URL, json=payload) as response:
                    if response.status != 200:
                        logger.error(f"OSV API error: {response.status} for {purl}")
                        return []

                    data = await response.json()
                    vulns_data = data.get("vulns", [])
                    return self._map_osv_to_model(vulns_data)
        except Exception as e:
            logger.exception(f"Failed to fetch vulnerabilities from OSV for {purl}: {e}")
            return []

    def _map_osv_to_model(self, vulns_data: List[dict]) -> List[Dict[str, Any]]:
        """
        Maps OSV API response to internal vulnerability format.
        """
        results = []
        for v in vulns_data:
            cve_id = v.get("id", "UNKNOWN")
            
            cvss_score = 0.0
            for severity in v.get("severity", []):
                if "score" in severity:
                    try:
                        cvss_score = float(severity["score"])
                        break
                    except (ValueError, TypeError):
                        continue
            
            affected_ranges = []
            for affected in v.get("affected", []):
                events = affected.get("ranges", [])
                for event in events:
                    type_ = event.get("type")
                    value = event.get("value")
                    if type_ and value:
                        affected_ranges.append(f"{type_}: {value}")
            
            fixed_in = None
            for affected in v.get("affected", []):
                for event in affected.get("ranges", []):
                    if event.get("type") == "fixed":
                        fixed_in = event.get("value")
                        break
            
            results.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": self._score_to_severity(cvss_score),
                "description": v.get("details", "No description available."),
                "affected_versions": affected_ranges,
                "fixed_in": fixed_in
            })
        return results

    def _score_to_severity(self, score: float) -> str:
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        if score > 0: return "LOW"
        return "Unknown"
