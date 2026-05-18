import logging
import requests
import os
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
from core.models import Component, Vulnerability

load_dotenv()
logger = logging.getLogger(__name__)

class CVEProviderPlugin:
    """
    Provides CVE vulnerability data based on CPE (Common Platform Enumeration) 
    identifiers using the NVD API.
    """
    def __init__(self, api_key: Optional[str] = None):
        # NVD API key helps avoid aggressive rate limiting
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
    def execute(self, cpe: str) -> List[Vulnerability]:
        """
        Queries the NVD API for CVEs associated with a given CPE string.
        """
        if not cpe or cpe == "Unknown":
            return []

        logger.info(f"Querying CVEs for CPE: {cpe}")
        
        try:
            # NVD API 2.0 uses the 'virtualMatchString' or 'cpeName' parameter
            params = {
                "cpeName": cpe,
                "resultsPerPage": 10  # Limit results for performance
            }
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            response = requests.get(self.base_url, params=params, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()

            vulnerabilities = []
            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                metrics = cve_data.get("metrics", {})
                
                # Try to get the CVSS score (prefer CVSS v3.1 -> v3.0 -> v2.0)
                severity = "Unknown"
                cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                if cvss_v3 and cvss_v3:
                    severity = cvss_v3[0].get("cvssData", {}).get("baseSeverity", "Unknown")

                vulnerabilities.append(Vulnerability(
                    cve_id=cve_data.get("id", "Unknown"),
                    severity=severity,
                    description=cve_data.get("descriptions", [{}])[0].get("value", "No description available"),
                    affected_versions=[], # More complex to extract from NVD JSON
                    exploits=[]
                ))

            return vulnerabilities

        except Exception as e:
            logger.error(f"Error fetching CVEs for {cpe}: {e}")
            return []
