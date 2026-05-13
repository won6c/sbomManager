import logging
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor

from core.models import (
    FullSystemScanResult, 
    KernelState, 
    DaemonAsset, 
    BinaryAsset, 
    PrivilegeLevel
)
from plugins.kernel.probe import KernelProbe
from plugins.daemons.probe import DaemonProbe
from plugins.binaries.probe import BinaryProbePlugin

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
        # We wrap the synchronous probe methods in run_in_executor
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
            daemons_assets.append(DaemonAsset(
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
            ))

        # 3. Process Binary Result
        binaries_assets = []
        for b in binaries_raw:
            binaries_assets.append(BinaryAsset(
                path=b.get("path", "Unknown"),
                sha256=b.get("sha256", "Unknown"),
                permissions=b.get("permissions", "Unknown"),
                is_setuid=b.get("is_setuid", False),
                is_setgid=b.get("is_setgid", False),
                mitigations=b.get("mitigations", {}),
                privilege_level=PrivilegeLevel.ROOT if b.get("is_setuid") or b.get("is_setgid") else PrivilegeLevel.USER,
                version=b.get("version")
            ))

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
        print("\n--- Full Result Detail ---")
        pprint.pprint(result)
    except Exception as e:
        print(f"\n[!] Async Scan failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Run the async test
    asyncio.run(test_run())
