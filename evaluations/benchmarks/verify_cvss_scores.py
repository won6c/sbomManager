
import os
from plugins.intelligence.cve_provider import CVEProviderPlugin
from dotenv import load_dotenv

load_dotenv()

def test_cvss_extraction():
    # Use a common service CPE (e.g., OpenSSH or similar known to have CVEs)
    test_cpes = [
        "cpe:2.3:a:openbsd:opensch-ssh:8.9p1:*:*:*:*:*:*:*", 
        "cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"
    ]
    
    provider = CVEProviderPlugin()
    
    for cpe in test_cpes:
        print(f"\nTesting CPE: {cpe}")
        vulns = provider.execute(cpe)
        print(f"Found {len(vulns)} vulnerabilities.")
        
        for v in vulns[:3]: # Print first 3 for brevity
            print(f"- {v.cve_id} | Severity: {v.severity} | Score: {v.cvss_score}")
            if v.cvss_score is None:
                print("  [!] Warning: CVSS Score is None")
            else:
                print(f"  [+] Success: Retrieved score {v.cvss_score}")

if __name__ == '__main__':
    test_cvss_extraction()
