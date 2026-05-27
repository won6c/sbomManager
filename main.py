from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Request
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from pathlib import Path
import uvicorn
import logging
import traceback
from datetime import datetime

from core.collector import SystemCollector
from core.models import (
    Component,
    CPERequest,
    CPEResponse,
    CVERequest,
    CVEResponse
)
from plugins.intelligence.cpe_resolver import CPEResolverPlugin
from plugins.intelligence.nvd_cve_provider import NvdCveProviderPlugin
from plugins.packages.reachability import ProcMapsReachabilityAnalyzer
from plugins.packages.osv import OSVCVEProvider
from plugins.packages.parsers import CycloneDXParser

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api")

app = FastAPI(title="SBOM Manager API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instance Management
collector = SystemCollector()
cpe_resolver = CPEResolverPlugin()
nvd_provider = NvdCveProviderPlugin()
reachability_analyzer = ProcMapsReachabilityAnalyzer()
osv_provider = OSVCVEProvider()
cyclone_parser = CycloneDXParser()

class ScanRequest(BaseModel):
    binary_scan_paths: List[str]

# --- Global Exception Handler ---
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {traceback.format_exc()}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "InternalServerError",
            "message": str(exc),
            "timestamp": datetime.utcnow().isoformat()
        }
    )

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/scan")
async def run_scan(request: ScanRequest):
    try:
        result = await collector.collect(request.binary_scan_paths)
        return jsonable_encoder(result)
    except Exception as e:
        raise e # Let global handler handle it

# --- API v1: Intelligence Endpoints ---

@app.post("/api/v1/intelligence/cpe")
async def resolve_cpe(req: CPERequest):
    try:
        comp = Component(name=req.name, version=req.version)
        resolved_comp = cpe_resolver.execute(comp)
        if not resolved_comp.cpe:
            raise HTTPException(status_code=404, detail="Could not resolve CPE.")
        return CPEResponse(
            name=req.name,
            version=req.version,
            cpe=resolved_comp.cpe,
            source="cache_or_heuristic",
            confidence=0.75
        )
    except HTTPException:
        raise
    except Exception as e:
        raise e

@app.post("/api/v1/intelligence/cve")
async def get_cves(req: CVERequest):
    try:
        comp = Component(name="unknown", version="unknown", cpe=req.cpe)
        vulns = nvd_provider.execute(comp)
        if req.min_severity:
            severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            min_rank = severity_order.get(req.min_severity.upper(), 0)
            vulns = [
                vuln for vuln in vulns
                if severity_order.get(vuln.severity.upper(), 0) >= min_rank
            ]
        if req.sort_by == "severity":
            severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            vulns = sorted(
                vulns,
                key=lambda vuln: (
                    severity_order.get(vuln.severity.upper(), 0),
                    vuln.cvss_score or 0.0
                ),
                reverse=True
            )
        total_count = len(vulns)
        paged_vulns = vulns[req.offset:req.offset + req.limit]
        return CVEResponse(
            cpe=req.cpe,
            vulnerabilities=paged_vulns,
            total_count=total_count,
            limit=req.limit,
            offset=req.offset
        )
    except Exception as e:
        raise e

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
    path = Path(file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="SBOM file not found.")
    
    if path.suffix == ".json":
        parser = CycloneDXParser()
        results = parser.parse(path)
        return {"format": "CycloneDX", "packages": results}
    else:
        raise HTTPException(status_code=400, detail="Unsupported SBOM format. Use .json for CycloneDX.")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
