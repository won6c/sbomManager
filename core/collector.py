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
    Component,
    Vulnerability
)
from plugins.kernel.probe import KernelProbe
from plugins.daemons.probe import DaemonProbe
from plugins.binaries.probe import BinaryProbePlugin
from plugins.intelligence.cpe_resolver import CPEResolverPlugin
from plugins.intelligence.nvd_cve_provider import NvdCveProviderPlugin
from plugins.packages.osv import OSVCVEProvider
from plugins.packages.reachability import ProcMapsReachabilityAnalyzer
from plugins.packages.parsers import PackageResolver
from plugins.packages.probe import PackageProbe
from core.risk_engine import RiskScoringEngine
from core.remediation import RemediationEngine

logger = logging.getLogger(__name__)

class SystemCollector:
    '''
    Orchestrates the discovery of system assets by coordinating 
    different probes (Kernel, Daemons, Binaries) and enriching them 
    with Intelligence (CPE, CVE, OSV) and Reachability analysis.
    '''
    def __init__(self):
        self.kernel_probe = KernelProbe()
        self.daemon_probe = DaemonProbe()
        self.binary_probe = BinaryProbePlugin()
        self.cpe_resolver = CPEResolverPlugin()
        self.nvd_provider = NvdCveProviderPlugin()
        self.osv_provider = OSVCVEProvider()
        self.package_resolver = PackageResolver()
        self.package_probe = PackageProbe()
        self.reachability = ProcMapsReachabilityAnalyzer()
        self.risk_engine = RiskScoringEngine()
        self.remediation_engine = RemediationEngine()
        
        self.executor = ThreadPoolExecutor(max_workers=5)

    async def _enrich_asset_vulnerabilities(self, asset_cpe: Optional[str], purl: Optional[str] = None) -> List[Vulnerability]:
        '''
        Enrich asset with vulnerabilities from both NVD and OSV.
        '''
        vulns = []
        
        # 1. NVD Query (Standard CPE based)
        if asset_cpe and asset_cpe != "Unknown":
            nvd_vulns = self.nvd_provider.execute(Component(name="temp", version="temp", cpe=asset_cpe))
            vulns.extend(nvd_vulns)
            
        # 2. OSV Query (PURL based)
        if purl:
            try:
                osv_raw = await self.osv_provider.fetch_vulnerabilities(purl)
                osv_vulns = [Vulnerability(**v) for v in osv_raw]
                vulns.extend(osv_vulns)
            except Exception as e:
                logger.error(f"OSV enrichment failed for {purl}: {e}")
        
        # Deduplicate by CVE ID
        seen = set()
        unique_vulns = []
        for v in vulns:
            if v.cve_id not in seen:
                unique_vulns.append(v)
                seen.add(v.cve_id)
        
        return unique_vulns

    async def collect(self, binary_scan_paths: List[str]) -> FullSystemScanResult:
        '''
        Performs a full system scan and returns a standardized result.
        '''
        loop = asyncio.get_running_loop()
        logger.info(f"Starting integrated system scan. Paths: {binary_scan_paths}")

        # Step 1: Parallel Discovery
        tasks = [
            loop.run_in_executor(self.executor, self.kernel_probe.probe),
            loop.run_in_executor(self.executor, self.daemon_probe.probe),
            loop.run_in_executor(self.executor, lambda: self.binary_probe.execute({"scan_paths": binary_scan_paths})),
            loop.run_in_executor(self.executor, lambda: self.package_probe.execute(binary_scan_paths, limit=250))
        ]
        kernel_raw, daemons_raw, binaries_raw, packages_assets = await asyncio.gather(*tasks)

        # Process Kernel
        kernel_state = KernelState(
            version=kernel_raw.get("version", "Unknown"),
            config=kernel_raw.get("config", {}),
            is_root=self.kernel_probe.is_root
        )

        # Process Daemons
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
            
            # Reachability Verification
            if asset.binary_path and asset.binary_path != "Unknown":
                is_loaded, regions = self.reachability.check_memory_load(asset.binary_path)
                asset.is_reachable = is_loaded
                asset.memory_regions = regions

            # OS Package Resolution (dpkg)
            if asset.binary_path and asset.binary_path != "Unknown":
                pkg_info = self.package_resolver.resolve_binary(asset.binary_path)
                if pkg_info:
                    if not asset.version or asset.version == "Unknown":
                        asset.version = pkg_info["version"]
                    if not asset.description or asset.description == "Unknown":
                        asset.description = pkg_info["package"]

            # Intelligence Enrichment
            name = asset.description or (asset.binary_path.split('/')[-1] if asset.binary_path != "Unknown" else None)
            if name and asset.version:
                # Sanitize name (nmap often adds '?' to uncertain services)
                clean_name = name.rstrip('?')
                comp = Component(name=clean_name, version=asset.version)
                resolved = self.cpe_resolver.execute(comp)
                asset.cpe = resolved.cpe
                
                # Construct a valid PURL (Package URL)
                from urllib.parse import quote
                safe_name = quote(clean_name)
                safe_version = quote(asset.version)
                purl = f"pkg:generic/{safe_name}@{safe_version}"
                asset.vulnerabilities = await self._enrich_asset_vulnerabilities(asset.cpe, purl)
            else:
                asset.cpe = "Unknown"
            
            daemons_assets.append(asset)

        # Process Binaries
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
            
            # Reachability Verification
            if asset.path and asset.path != "Unknown":
                is_loaded, regions = self.reachability.check_memory_load(asset.path)
                asset.is_reachable = is_loaded
                asset.memory_regions = regions

            # OS Package Resolution (dpkg)
            if asset.path and asset.path != "Unknown":
                pkg_info = self.package_resolver.resolve_binary(asset.path)
                if pkg_info:
                    if not asset.version or asset.version == "Unknown":
                        asset.version = pkg_info["version"]

            # Intelligence Enrichment
            name = os.path.basename(asset.path) if asset.path != "Unknown" else None
            if name and asset.version:
                clean_name = name.rstrip('?')
                comp = Component(name=clean_name, version=asset.version)
                resolved = self.cpe_resolver.execute(comp)
                asset.cpe = resolved.cpe
                
                from urllib.parse import quote
                safe_name = quote(clean_name)
                safe_version = quote(asset.version)
                purl = f"pkg:generic/{safe_name}@{safe_version}"
                asset.vulnerabilities = await self._enrich_asset_vulnerabilities(asset.cpe, purl)
            else:
                asset.cpe = "Unknown"
                
            binaries_assets.append(asset)

        scan_result = FullSystemScanResult(
            kernel=kernel_state,
            daemons=daemons_assets,
            binaries=binaries_assets,
            packages=packages_assets,
            timestamp=datetime.now().isoformat()
        )
        
        # Calculate Risk Scores (Now aware of Reachability)
        analyzed = self.risk_engine.analyze_system(scan_result)
        analyzed.remediation = self.remediation_engine.recommend(analyzed)
        return analyzed
