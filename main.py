from fastapi import FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from typing import List
import uvicorn
from core.collector import SystemCollector

app = FastAPI(title="SBOM Manager API")
collector = SystemCollector()

class ScanRequest(BaseModel):
    binary_scan_paths: List[str]

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/scan")
async def run_scan(request: ScanRequest):
    try:
        # Use the core collector to perform an async system scan
        result = await collector.collect(request.binary_scan_paths)
        
        # Use jsonable_encoder to prevent recursion errors and ensure API compatibility
        return jsonable_encoder(result)
    except Exception as e:
        import traceback
        logger.error(f"Scan error: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

import logging
logger = logging.getLogger("api")
logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
