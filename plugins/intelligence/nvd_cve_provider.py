import os
import requests
import time
import json
import logging
from typing import List, Optional, Dict, Any
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from dotenv import load_dotenv
from core.models import Component, Vulnerability
from core.storage import CVEStorage

load_dotenv()

logger = logging.getLogger(__name__)

class NvdCveProviderPlugin:
    """
    Real-world plugin for fetching live CVE data from the NVD API (v2.0) with SQLite caching.
    """
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        if self.api_key:
            logger.info("NVD Provider initialized with API Key (Higher rate limits).")
            self.request_delay = 0.65 
        else:
            logger.info("NVD Provider initialized WITHOUT API Key (Rate limited to 5 req / 30s).")
            self.request_delay = 6.1 
        
        # Setup SQLite Storage instead of file cache
        self.storage = CVEStorage()
        
        # Setup HTTP session with retry logic
        self.session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=2,
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
        Queries the NVD API for vulnerabilities matching the component's CPE with SQLite caching.
        """
        if not component.cpe:
            logger.warning(f"Component {component.name} has no CPE. Cannot query NVD.")
            return []

        # 1. Check SQLite Storage First
        cached_data = self.storage.get(component.cpe)
        if cached_data is not None:
            return [Vulnerability(**vuln) for vuln in cached_data]
        
        # 2. Fetch from API
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
                # Cache empty result to avoid repeated 404 calls
                self.storage.set(component.cpe, [])
                return []
                
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities_raw = []
            vulnerabilities_objs = []
            
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                
                descriptions = cve.get("descriptions", [])
                description = next(
                    (d.get("value") for d in descriptions if d.get("lang") == "en"), 
                    "No description available."
                )
                
                metrics = cve.get("metrics", {})
                severity = "Unknown"
                
                cvss_v31 = metrics.get("cvssMetricV31", [])
                if cvss_v31:
                    severity = cvss_v31[0].get("cvssData", {}).get("baseSeverity", "Unknown")
                else:
                    cvss_v30 = metrics.get("cvssMetricV30", [])
                    if cvss_v30:
                        severity = cvss_v30[0].get("cvssData", {}).get("baseSeverity", "Unknown")
                    else:
                        cvss_v2 = metrics.get("cvssMetricV2", [])
                        if cvss_v2:
                            severity = cvss_v2[0].get("baseScore", "Unknown")
                            if isinstance(severity, (int, float)):
                                if severity >= 7.0: severity = "HIGH"
                                elif severity >= 4.0: severity = "MEDIUM"
                                else: severity = "LOW"

                vuln_data = {
                    "cve_id": cve_id,
                    "severity": severity,
                    "description": description,
                    "affected_versions": [component.version] if component.version else []
                }
                vulnerabilities_raw.append(vuln_data)
                vulnerabilities_objs.append(Vulnerability(**vuln_data))
            
            # 3. Update SQLite Storage
            self.storage.set(component.cpe, vulnerabilities_raw)
                
            return vulnerabilities_objs
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying NVD API for {component.cpe}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error in NVD provider: {e}")
            return []
