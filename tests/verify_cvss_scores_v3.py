
import os
import logging
import sys
from plugins.intelligence.cve_provider import CVEProviderPlugin
from dotenv import load_dotenv

# Setup logging to see exactly what's happening
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
load_dotenv()

def test_cvss_extraction():
    # A known vulnerable CPE for Apache HTTP Server
    test_cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    print(f"--- Testing CVE Provider ---")
    print(f"Target CPE: {test_cpe}")
    
    provider = CVEProviderPlugin()
    print(f"API Key present: {'Yes' if provider.api_key else 'No'}")
    
    try:
        print("Calling provider.execute()...")
        vulns = provider.execute(test_cpe)
        print(f"CPE Execution Finished. Found {len(vulns)} vulnerabilities.")
        
        if not vulns:
            print("Result: Empty list returned. Check if the CPE is valid in NVD.")
            return

        for i, v in enumerate(vulns[:5]):
            print(f"[{i}] ID: {v.cve_id} | Sev: {v.severity} | Score: {v.cvss_score}")
            if v.cvss_score is not None:
                print(f"    [SUCCESS] CVSS Score retrieved: {v.cvss_score}")
            else:
                print(f"    [FAILURE] CVSS Score is missing!")

    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_cvss_extraction()
