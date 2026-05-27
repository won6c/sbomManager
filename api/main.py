from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import uuid
import logging
from core.pipeline import Pipeline
from core.plugin_manager import PluginManager
from core.models import MappingResult

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sbom_api")

app = FastAPI(title="SBOM Manager API", version="1.0.0")

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for results (Replace with DB in production)
results_db = {}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/trigger/pipeline")
async def trigger_pipeline(background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    results_db[scan_id] = {"status": "processing", "data": None}
    
    background_tasks.add_task(run_pipeline, scan_id)
    
    return {"scan_id": scan_id, "status": "started"}

@app.get("/results/{scan_id}")
async def get_results(scan_id: str):
    if scan_id not in results_db:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return results_db[scan_id]

async def run_pipeline(scan_id: str):
    try:
        logger.info(f"Starting pipeline for scan {scan_id}")
        
        # Initialize Core
        pm = PluginManager()
        # Discover and load plugins from the plugins directory
        plugins_dir = "plugins"
        discovered = pm.discover_plugins(plugins_dir)
        for p_name in discovered:
             # Try to load from top level plugins or subdirectories
             try:
                 pm.load_plugin(f"plugins.{p_name}")
             except:
                 pass

        pipeline = Pipeline()
        
        # Basic pipeline handlers for the purpose of a functional end-to-end flow
        # In reality, these would be linked to the plugins loaded by pm
        def mock_parse(data): return [{"name": "openssl", "version": "1.1.1", "category": "Package"}]
        def mock_enrich(data): 
            for item in data: item["cpe"] = "cpe:2.3:a:openssl:openssl:1.1.1"
            return data
        def mock_map(data):
            for item in data: item["vulnerabilities"] = [{"id": "CVE-2023-1234", "severity": "High"}]
            return data
        def mock_export(data): return data

        from core.pipeline import PipelineStage
        
        pipeline.add_stage(PipelineStage.PARSE, mock_parse)
        pipeline.add_stage(PipelineStage.ENRICH, mock_enrich)
        pipeline.add_stage(PipelineStage.MAP, mock_map)
        pipeline.add_stage(PipelineStage.EXPORT, mock_export)
        
        results = pipeline.run(None) 
        
        results_db[scan_id] = {
            "status": "completed",
            "data": results
        }
        logger.info(f"Pipeline completed successfully for scan {scan_id}")
    except Exception as e:
        logger.error(f"Pipeline failed for scan {scan_id}: {str(e)}")
        results_db[scan_id] = {
            "status": "failed",
            "error": str(e)
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
