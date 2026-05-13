import os
import sys
import logging
from typing import List, Dict, Any, Optional

from core.models import Component, Vulnerability, MappingResult
from core.pipeline import Pipeline, PipelineStage
from plugins.kernel.probe import KernelProbe
from plugins.binaries.probe import BinaryProbePlugin
from plugins.daemons.probe import DaemonProbe
from plugins.intelligence.cpe_resolver import CPEResolverPlugin
from plugins.intelligence.nvd_cve_provider import NvdCveProviderPlugin
from plugins.intelligence.metasploit_provider import MetasploitProviderPlugin

# Configure logging to be less intrusive during interactive use
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger("InteractiveAnalyzer")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

class InteractiveAnalyzer:
    def __init__(self):
        self.cpe_resolver = CPEResolverPlugin()
        self.cve_provider = NvdCveProviderPlugin()
        self.msf_provider = MetasploitProviderPlugin()
        self.discovered_items = []

    def run_discovery(self):
        print("[*] Running System Discovery Probes...")
        
        # 1. Kernel Probe
        print("    > Probing Kernel...", end="\r")
        k_probe = KernelProbe()
        k_res = k_probe.probe()
        self.discovered_items.append({
            "type": "KERNEL",
            "name": "linux-kernel",
            "version": k_res.get("version"),
            "details": f"Config options: {len(k_res.get('config', {}))}"
        })
        
        # 2. Daemon Probe
        print("    > Probing Listening Daemons...", end="\r")
        d_probe = DaemonProbe()
        d_res = d_probe.probe()
        for d in d_res:
            name = d.get("unit") or d.get("description") or "Unknown Service"
            # Clean up unit names (e.g., ssh.service -> ssh)
            if isinstance(name, str) and name.endswith(".service"):
                name = name[:-8]
                
            self.discovered_items.append({
                "type": "DAEMON",
                "name": name,
                "version": d.get("version"), 
                "details": f"Port: {d.get('port')} ({d.get('protocol')}), Path: {d.get('binary_path')}",
                "path": d.get("binary_path")
            })

        # 3. Binary Probe (Limited to common locations for speed)
        print("    > Probing Binaries (/usr/local/bin)...", end="\r")
        b_probe = BinaryProbePlugin()
        b_res = b_probe.execute({"scan_paths": ["/usr/local/bin"]})
        for b in b_res[:20]: # Limit to first 20 to avoid overwhelming the menu
            path = b.get("path", "")
            name = os.path.basename(path)
            self.discovered_items.append({
                "type": "BINARY",
                "name": name,
                "version": b.get("version"),
                "details": f"SHA256: {b.get('sha256')[:12]}...",
                "path": path
            })
            
        print("[+] Discovery Complete. Found {} items.".format(len(self.discovered_items)))

    def display_menu(self):
        print("\n" + "="*60)
        print("{:<5} {:<10} {:<20} {:<15} {:<20}".format("ID", "TYPE", "NAME", "VERSION", "DETAILS"))
        print("-" * 60)
        
        for i, item in enumerate(self.discovered_items):
            version = item["version"] or "[Not Found]"
            print("{:<5} {:<10} {:<20} {:<15} {:<20}".format(
                i, item["type"], item["name"][:19], version[:14], item["details"][:20]
            ))
        print("="*60)

    def analyze_item(self, index: int):
        if index < 0 or index >= len(self.discovered_items):
            print("[!] Invalid selection.")
            return

        item = self.discovered_items[index]
        name = item["name"]
        version = item["version"]

        print(f"\n[*] Analyzing: {name}")
        
        # If version is missing, ask user
        if not version:
            version = input(f"    [?] Enter version for {name} (leave blank to skip): ").strip()
            if not version:
                print("[!] Analysis cancelled: Version required for CVE mapping.")
                return
            item["version"] = version

        # Create Component
        comp = Component(name=name, version=version)
        
        # Run Pipeline
        print(f"[*] Resolving CPE for {name} v{version}...")
        comp = self.cpe_resolver.execute(comp)
        
        if not comp.cpe:
            print("[!] Could not resolve CPE. Try a more specific name.")
            manual_cpe = input("    [?] Enter CPE manually (or press Enter to skip): ").strip()
            if manual_cpe:
                comp.cpe = manual_cpe
            else:
                return

        print(f"[+] CPE: {comp.cpe}")
        
        print("[*] Querying NVD for Live CVEs...")
        vulns = self.cve_provider.execute(comp)
        
        if not vulns:
            print("[+] No known vulnerabilities found for this version.")
            return

        print(f"[!] Found {len(vulns)} vulnerabilities. Checking for exploits...")
        self.msf_provider.execute(vulns)
        
        # Display Results
        print("\n" + "VULNERABILITY REPORT".center(60, "-"))
        for v in vulns:
            exploit_status = "EXPLOIT AVAILABLE" if v.exploits else "No known MSF exploit"
            print(f"\n[{v.cve_id}] {v.severity} - {exploit_status}")
            print(f"Description: {v.description[:100]}...")
            if v.exploits:
                for ex in v.exploits:
                    print(f"  -> Exploit: {ex['name']} ({ex['rank']})")
        print("-" * 60)

    def main_loop(self):
        clear_screen()
        print("SBOM Manager - Interactive System Security Analyzer")
        self.run_discovery()
        
        while True:
            self.display_menu()
            choice = input("\nEnter ID to analyze (or 'q' to quit, 'r' to refresh): ").lower().strip()
            
            if choice == 'q':
                break
            if choice == 'r':
                self.discovered_items = []
                self.run_discovery()
                continue
                
            try:
                idx = int(choice)
                self.analyze_item(idx)
                input("\nPress Enter to return to menu...")
                clear_screen()
            except ValueError:
                print("[!] Please enter a valid number.")

if __name__ == "__main__":
    analyzer = InteractiveAnalyzer()
    try:
        analyzer.main_loop()
    except KeyboardInterrupt:
        print("\n[!] Exiting...")
        sys.exit(0)
