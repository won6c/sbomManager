import os
import requests
import time
import logging
from typing import List, Optional, Dict, Any
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from dotenv import load_dotenv
from core.models import Component, Vulnerability

load_dotenv()

logger = logging.getLogger(__name__)

class NvdCveProviderPlugin:
    """
    Real-world plugin for fetching live CVE data from the NVD API (v2.0).
    """
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        if self.api_key:
            logger.info("NVD Provider initialized with API Key (Higher rate limits).")
            # 50 requests per 30 seconds -> ~0.6s per request
            self.request_delay = 0.65 
        else:
            logger.info("NVD Provider initialized WITHOUT API Key (Rate limited to 5 req / 30s).")
            # 5 requests per 30 seconds -> 6s per request
            self.request_delay = 6.1 
        
        # Setup HTTP session with retry logic
        self.session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=2, # Exponential backoff
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retries))
        
        self.last_request_time = 0.0

    def _get_headers(self) -> Dict[str, str]:
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _wait_for_rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.request_delay:
            time.sleep(self.request_delay - elapsed)
        self.last_request_time = time.time()

    def execute(self, component: Component) -> List[Vulnerability]:
        """
        Queries the NVD API for vulnerabilities matching the component's CPE.
        """
        if not component.cpe:
            logger.warning(f"Component {component.name} has no CPE. Cannot query NVD.")
            return []

        self._wait_for_rate_limit()
        
        try:
            params = {"cpeName": component.cpe}
            response = self.session.get(
                self.base_url, 
                params=params, 
                headers=self._get_headers(),
                timeout=15
            )
            
            if response.status_code == 404:
                return []
                
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                
                # Extract description (English)
                descriptions = cve.get("descriptions", [])
                description = next(
                    (d.get("value") for d in descriptions if d.get("lang") == "en"), 
                    "No description available."
                )
                
                # Extract severity from CVSS v3.1, v3.0, or v2
                metrics = cve.get("metrics", {})
                severity = "Unknown"
                
                # Try CVSS v3.1 first
                cvss_v31 = metrics.get("cvssMetricV31", [])
                if cvss_v31:
                    severity = cvss_v31[0].get("cvssData", {}).get("baseSeverity", "Unknown")
                else:
                    # Try CVSS v3.0
                    cvss_v30 = metrics.get("cvssMetricV30", [])
                    if cvss_v30:
                        severity = cvss_v30[0].get("cvssData", {}).get("baseSeverity", "Unknown")
                    else:
                        # Fallback to CVSS v2
                        cvss_v2 = metrics.get("cvssMetricV2", [])
                        if cvss_v2:
                            severity = cvss_v2[0].get("baseScore", "Unknown")
                            # Convert numerical score to label if it's a number
                            if isinstance(severity, (int, float)):
                                if severity >= 7.0: severity = "HIGH"
                                elif severity >= 4.0: severity = "MEDIUM"
                                else: severity = "LOW"

                vulnerabilities.append(Vulnerability(
                    cve_id=cve_id,
                    severity=severity,
                    description=description,
                    affected_versions=[component.version] if component.version else []
                ))
                
            return vulnerabilities

        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying NVD API for {component.cpe}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error in NVD provider: {e}")
            return []
