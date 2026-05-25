from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from typing import List, Optional
from pathlib import Path
import uvicorn
import logging

from core.collector import SystemCollector
from core.models import Component, Vulnerability
from plugins.intelligence.cpe_resolver import CPEResolverPlugin
from plugins.intelligence.nvd_cve_provider import NvdCveProviderPlugin
from plugins.packages.reachability import ProcMapsReachabilityAnalyzer
from plugins.packages.osv import OSVCVEProvider
from plugins.packages.parsers import CycloneDXParser

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api")

app = FastAPI(title="SBOM Manager API")

# Instance Management
collector = SystemCollector()
cpe_resolver = CPEResolverPlugin()
nvd_provider = NvdCveProviderPlugin()
reachability_analyzer = ProcMapsReachabilityAnalyzer()
osv_provider = OSVCVEProvider()
cyclone_parser = CycloneDXParser()

class ScanRequest(BaseModel):
    binary_scan_paths: List[str]

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/scan")
async def run_scan(request: ScanRequest):
    try:
        result = await collector.collect(request.binary_scan_paths)
        return jsonable_encoder(result)
    except Exception as e:
        import traceback
        logger.error(f"Scan error: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

# --- Intelligence Endpoints ---

@app.get("/intelligence/cpe")
async def resolve_cpe(name: str = Query(...), version: str = Query(...)):
    try:
        comp = Component(name=name, version=version)
        resolved_comp = cpe_resolver.execute(comp)
        if not resolved_comp.cpe:
            raise HTTPException(status_code=404, detail="Could not resolve CPE.")
        return {"name": name, "version": version, "cpe": resolved_comp.cpe}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/intelligence/cve")
async def get_cves(cpe: str = Query(...)):
    try:
        comp = Component(name="unknown", version="unknown", cpe=cpe)
        vulnerabilities = nvd_provider.execute(comp)
        return {"cpe": cpe, "vulnerabilities": jsonable_encoder(vulnerabilities), "count": len(vulnerabilities)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/intelligence/cache/refresh")
async def refresh_cache(background_tasks: BackgroundTasks, cpe: Optional[str] = Query(None)):
    def background_refresh(target_cpe: Optional[str]):
        if target_cpe:
            try:
                from core.storage import CVEStorage
                storage = CVEStorage()
                import sqlite3
                with sqlite3.connect(storage.db_path) as conn:
                    conn.execute("DELETE FROM cpe_cache WHERE cpe = ?", (target_cpe,))
                comp = Component(name="refresh", version="refresh", cpe=target_cpe)
                nvd_provider.execute(comp)
            except Exception as e:
                logger.error(f"Background refresh failed: {e}")
        else:
            try:
                from core.storage import CVEStorage
                CVEStorage().cleanup_expired()
            except Exception as e:
                logger.error(f"Background cleanup failed: {e}")

    background_tasks.add_task(background_refresh, cpe)
    return {"status": "refresh_started", "target": cpe if cpe else "all_expired"}

# --- New Package Feature Endpoints ---

@app.get("/intelligence/reachability")
async def check_reachability(path: str = Query(...)):
    """
    Check if a specific file path is currently loaded in any process's memory.
    """
    is_loaded, regions = reachability_analyzer.check_memory_load(path)
    executable = reachability_analyzer.verify_executable_region(regions) if is_loaded else False
    return {
        "path": path,
        "is_loaded": is_loaded,
        "is_executable": executable,
        "memory_regions": regions
    }

@app.get("/intelligence/osv")
async def query_osv(purl: str = Query(...)):
    """
    Query OSV database for vulnerabilities using a PURL.
    """
    try:
        vulns = await osv_provider.fetch_vulnerabilities(purl)
        return {
            "purl": purl,
            "vulnerabilities": jsonable_encoder(vulns),
            "count": len(vulns)
        }
    except Exception as e:
        logger.error(f"OSV Query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/intelligence/sbom/parse")
async def parse_sbom(file_path: str = Query(...)):
    """
    Parse a CycloneDX or SPDX SBOM file and return the package list.
    """
    path = Path(file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="SBOM file not found.")
    
    # Currently supports CycloneDX JSON
    if path.suffix == ".json":
        parser = CycloneDXParser()
        results = parser.parse(path)
        return {"format": "CycloneDX", "packages": results}
    else:
        raise HTTPException(status_code=400, detail="Unsupported SBOM format. Use .json for CycloneDX.")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
