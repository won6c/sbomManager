import logging
import asyncio
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor

from core.models import (
    FullSystemScanResult, 
    KernelState, 
    DaemonAsset, 
    BinaryAsset, 
    PrivilegeLevel,
    Component
)
from plugins.kernel.probe import KernelProbe
from plugins.daemons.probe import DaemonProbe
from plugins.binaries.probe import BinaryProbePlugin
from plugins.intelligence.cpe_resolver import CPEResolverPlugin
from plugins.intelligence.cve_provider import CVEProviderPlugin

logger = logging.getLogger(__name__)

class SystemCollector:
    '''
    Orchestrates the discovery of system assets by coordinating 
    different probes (Kernel, Daemons, Binaries) asynchronously.
    '''

    def __init__(self):
        self.kernel_probe = KernelProbe()
        self.daemon_probe = DaemonProbe()
        self.binary_probe = BinaryProbePlugin()
        self.cpe_resolver = CPEResolverPlugin()
        self.cve_provider = CVEProviderPlugin()
        # Using ThreadPoolExecutor because probe tools (nmap, psutil, os.walk) are synchronous I/O bound
        self.executor = ThreadPoolExecutor(max_workers=5)

    async def collect(self, binary_scan_paths: List[str]) -> FullSystemScanResult:
        '''
        Performs a full system scan asynchronously and returns a standardized result.
        :param binary_scan_paths: List of absolute paths to scan for binaries.
        '''
        loop = asyncio.get_running_loop()
        logger.info(f"Starting asynchronous full system scan. Target binary paths: {binary_scan_paths}")

        # Schedule all probes to run in parallel in the thread pool
        tasks = [
            loop.run_in_executor(self.executor, self.kernel_probe.probe),
            loop.run_in_executor(self.executor, self.daemon_probe.probe),
            loop.run_in_executor(self.executor, lambda: self.binary_probe.execute({"scan_paths": binary_scan_paths}))
        ]

        # Wait for all probes to complete
        kernel_raw, daemons_raw, binaries_raw = await asyncio.gather(*tasks)

        # 1. Process Kernel Result
        kernel_state = KernelState(
            version=kernel_raw.get("version", "Unknown"),
            config=kernel_raw.get("config", {}),
            is_root=self.kernel_probe.is_root
        )

        # 2. Process Daemon Result
        daemons_assets = []
        for d in daemons_raw:
            asset = DaemonAsset(
                port=d.get("port"),
                protocol=d.get("protocol"),
                address=d.get("address", "Unknown"),
                exposure=d.get("exposure", "Unknown"),
                pid=d.get("pid"),
                binary_path=d.get("binary_path", "Unknown"),
                user=d.get("user", "Unknown"),
                description=d.get("description"),
                version=d.get("version"),
                privilege_level=PrivilegeLevel.ROOT if d.get("user") == "root" else PrivilegeLevel.USER
            )
            
            # Enrich with CPE
            name = asset.description or (asset.binary_path.split('/')[-1] if asset.binary_path != "Unknown" else None)
            if name and name.lower() not in ["unknown", "unknown service"] and asset.version:
                comp = Component(name=name, version=asset.version)
                resolved = self.cpe_resolver.execute(comp)
                asset.cpe = resolved.cpe 
                
                # Enrich with CVE if CPE exists
                if asset.cpe and asset.cpe != "Unknown":
                    asset.vulnerabilities = self.cve_provider.execute(asset.cpe)
            else:
                asset.cpe = "Unknown"
            
            daemons_assets.append(asset)

        # 3. Process Binary Result
        binaries_assets = []
        for b in binaries_raw:
            asset = BinaryAsset(
                path=b.get("path", "Unknown"),
                sha256=b.get("sha256", "Unknown"),
                permissions=b.get("permissions", "Unknown"),
                is_setuid=b.get("is_setuid", False),
                is_setgid=b.get("is_setgid", False),
                mitigations=b.get("mitigations", {}),
                privilege_level=PrivilegeLevel.ROOT if b.get("is_setuid") or b.get("is_setgid") else PrivilegeLevel.USER,
                version=b.get("version")
            )
            
            # Enrich with CPE
            name = os.path.basename(asset.path) if asset.path != "Unknown" else None
            if name and asset.version:
                comp = Component(name=name, version=asset.version)
                resolved = self.cpe_resolver.execute(comp)
                asset.cpe = resolved.cpe
                
                # Enrich with CVE if CPE exists
                if asset.cpe and asset.cpe != "Unknown":
                    asset.vulnerabilities = self.cve_provider.execute(asset.cpe)
            else:
                asset.cpe = "Unknown"
                
            binaries_assets.append(asset)

        return FullSystemScanResult(
            kernel=kernel_state,
            daemons=daemons_assets,
            binaries=binaries_assets,
            timestamp=datetime.now().isoformat()
        )

async def test_run():
    '''
    Local test runner to verify the asynchronous collection logic.
    '''
    import pprint
    logging.basicConfig(level=logging.INFO)
    
    collector = SystemCollector()
    test_paths = ["/usr/local/bin", "/bin"] 
    print(f"[*] Starting Async Test with paths: {test_paths}...")
    
    try:
        result = await collector.collect(test_paths)
        print("\n[+] Async Scan completed successfully!")
        print(f"- Kernel: {result.kernel.version}")
        print(f"- Daemons found: {len(result.daemons)}")
        print(f"- Binaries found: {len(result.binaries)}")
        print("\n--- FULL DETAILED RESULT ---")
        
        print("\n[DAEMONS]")
        for d in result.daemons:
            print(f"Port {d.port} ({d.protocol}): {d.description} | Version: {d.version} | CPE: {d.cpe} | CVEs: {len(d.vulnerabilities)}")
            for v in d.vulnerabilities:
                print(f"   -> {v.cve_id} [{v.severity}] {v.description[:100]}...")

        print("\n[BINARIES]")
        for b in result.binaries:
            print(f"Path {b.path} | CPE: {b.cpe} | CVEs: {len(b.vulnerabilities)}")
            for v in b.vulnerabilities:
                print(f"   -> {v.cve_id} [{v.severity}] {v.description[:100]}...")

    except Exception as e:
        print(f"\n[!] Async Scan failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Run the async test
    asyncio.run(test_run())
