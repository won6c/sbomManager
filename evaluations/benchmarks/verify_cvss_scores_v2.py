
import os
import sys
from plugins.intelligence.cve_provider import CVEProviderPlugin
from dotenv import load_dotenv

load_dotenv()

def test_cvss_extraction():
    # Using a generic a-apache-http_server CPE for tests
    test_cpe = "cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"
    print(f"Target CPE: {test_cpe}")
    
    provider = CVEProviderPlugin()
    print(f"API Key used: {'Yes' if provider.api_key else 'No'}")
    
    try:
        vulns = provider.execute(test_cpe)
        print(f"Found {len(vulns)} vulnerabilities.")
        
        if not vulns:
            print("No vulnerabilities found for this CPE. Please check NVD API key or CPE string.")
            return

        for v in vulns[:5]:
            print(f"ID: {v.cve_id} | Sev: {v.severity} | Score: {v.cvss_score}")
    except Exception as e:
        print(f"Error during execution: {e}")

if __name__ == '__main__':
    test_cvss_extraction()
