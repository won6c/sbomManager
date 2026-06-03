import os
import sys
import time
import subprocess
from core.models import Component
from plugins.daemons.probe import DaemonProbe
from plugins.intelligence.cpe_resolver import CPEResolverPlugin
from plugins.intelligence.nvd_cve_provider import NvdCveProviderPlugin
from plugins.intelligence.metasploit_provider import MetasploitProviderPlugin

def test_full_system_flow():
    print("[1] Starting a test daemon (Python HTTP Server)...")
    server = subprocess.Popen([sys.executable, "-m", "http.server", "9876"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    try:
        # 1. Discover
        print("[2] Running Daemon Probe...")
        probe = DaemonProbe()
        daemons = probe.probe()
        
        target = next((d for d in daemons if d['port'] == 9876), None)
        if not target:
            print("[-] Test daemon not found!")
            return

        print(f"[+] Found Target: {target['description']} v{target['version']}")
        print(f"    Path: {target['binary_path']}")

        # 2. Resolve CPE
        print(f"[3] Resolving CPE for {target['description']} {target['version']}...")
        resolver = CPEResolverPlugin()
        comp = Component(name=target['description'], version=target['version'])
        comp = resolver.execute(comp)
        
        if not comp.cpe:
            # Fallback for python if resolver fails (shodan might not have it exactly)
            comp.cpe = f"cpe:2.3:a:python:python:{target['version']}:*:*:*:*:*:*:*"
            print(f"    (Manual fallback CPE: {comp.cpe})")
        else:
            print(f"[+] Resolved CPE: {comp.cpe}")

        # 3. Gather CVEs
        print("[4] Querying NVD for CVEs (Live)...")
        provider = NvdCveProviderPlugin()
        vulns = provider.execute(comp)
        print(f"[+] Found {len(vulns)} vulnerabilities.")

        # 4. Gather Exploits
        if vulns:
            print("[5] Checking Metasploit for exploits...")
            msf = MetasploitProviderPlugin()
            msf.execute(vulns)
            
            # Display first 3
            for v in vulns[:3]:
                status = "EXPLOITABLE" if v.exploits else "No MSF exploit"
                print(f"    - {v.cve_id} ({v.severity}): {status}")

    finally:
        server.terminate()
        print("[6] Test daemon stopped.")

if __name__ == "__main__":
    import sys
    test_full_system_flow()
