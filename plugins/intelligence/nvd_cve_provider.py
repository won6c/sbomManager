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
        return self.execute_with_options(component, limit=10, offset=0)

    def execute_with_options(
        self,
        component: Component,
        limit: int = 10,
        offset: int = 0,
        min_severity: Optional[str] = None,
        sort_by: str = "severity"
    ) -> List[Vulnerability]:
        """
        Enhanced query method with pagination, filtering, and sorting.
        """
        if not component.cpe:
            logger.warning(f"Component {component.name} has no CPE. Cannot query NVD.")
            return []

<<<<<<< Updated upstream
=======
        # 1. Get all vulnerabilities for this CPE (Cached or API)
        cached_data = self.storage.get(component.cpe)
        if cached_data is not None:
            all_vulns = [Vulnerability(**vuln) for vuln in cached_data]
        else:
            all_vulns = self._fetch_from_api(component)

        if not all_vulns:
            return []

        # 2. Filtering by Severity
        if min_severity:
            severity_map = {"Unknown": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            min_val = severity_map.get(min_severity.upper(), 0)
            all_vulns = [v for v in all_vulns if severity_map.get(v.severity.upper(), 0) >= min_val]

        # 3. Sorting
        if sort_by == "severity":
            severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "Unknown": 0}
            all_vulns.sort(key=lambda v: severity_map.get(v.severity.upper(), 0), reverse=True)
        else:
            all_vulns.sort(key=lambda v: v.cve_id)

        # 4. Pagination
        return all_vulns[offset : offset + limit]

    def _fetch_from_api(self, component: Component) -> List[Vulnerability]:
        """
        Internal method to handle the actual NVD API call.
        """
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
=======
                self.storage.set(component.cpe, [])
>>>>>>> Stashed changes
                return []

            response.raise_for_status()
            data = response.json()
<<<<<<< Updated upstream
            
            vulnerabilities = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                
                # Extract description (English)
=======

            vulnerabilities_raw = []
            vulnerabilities_objs = []

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id")

>>>>>>> Stashed changes
                descriptions = cve.get("descriptions", [])
                description = next(
                    (d.get("value") for d in descriptions if d.get("lang") == "en"),
                    "No description available."
                )
<<<<<<< Updated upstream
                
                # Extract severity from CVSS v3.1, v3.0, or v2
                metrics = cve.get("metrics", {})
                severity = "Unknown"
                
                # Try CVSS v3.1 first
=======

                metrics = cve.get("metrics", {})
                severity = "Unknown"

>>>>>>> Stashed changes
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

<<<<<<< Updated upstream
                vulnerabilities.append(Vulnerability(
                    cve_id=cve_id,
                    severity=severity,
                    description=description,
                    affected_versions=[component.version] if component.version else []
                ))
                
            return vulnerabilities
=======
                vuln_data = {
                    "cve_id": cve_id,
                    "severity": severity,
                    "description": description,
                    "affected_versions": [component.version] if component.version else []
                }
                vulnerabilities_raw.append(vuln_data)
                vulnerabilities_objs.append(Vulnerability(**vuln_data))

            self.storage.set(component.cpe, vulnerabilities_raw)
            return vulnerabilities_objs
>>>>>>> Stashed changes

        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying NVD API for {component.cpe}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error in NVD provider: {e}")
            return []
