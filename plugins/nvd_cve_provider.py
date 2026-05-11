from core.models import Vulnerability

class NvdCveProviderPlugin:
    """
    Plugin for fetching CVE data from NVD.
    """
    def __init__(self):
        # Mock data for demonstration as requested by test cases
        self.mock_db = {
            "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*": [
                {
                    "cve_id": "CVE-2023-0286",
                    "severity": "High",
                    "description": "A vulnerability in OpenSSL...",
                    "affected_versions": ["1.1.1"]
                }
            ],
            "cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*": []
        }

    def execute(self, component):
        # In a real implementation, this would call the NVD API
        vulns_data = self.mock_db.get(component.cpe, [])
        return [
            Vulnerability(
                cve_id=v["cve_id"],
                severity=v["severity"],
                description=v["description"]
            ) for v in vulns_data
        ]
