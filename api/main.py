import os
import uuid
import json
import hashlib
import asyncio
import tempfile
import base64
from fastapi import FastAPI, UploadFile, File, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse
from dotenv import load_dotenv

from agent.loop import run_analysis
from agent.model import get_model_backend
from tools.db_cache import init_db, lookup_cache, store_result, get_cached_image

load_dotenv()

app = FastAPI(title="MalWhere", description="PE Malware Analysis Agent")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()

@app.get("/health")
def health():
    return {"status": "ok", "model_backend": get_model_backend()}

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    """Upload PE file, run full analysis, return result."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    if not file.filename.lower().endswith((".exe", ".dll")):
        raise HTTPException(status_code=400, detail="Only .exe and .dll files accepted")
    
    # Save to temp path inside OS temp directory
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, f"{uuid.uuid4()}_{file.filename}")
    
    try:
        content = await file.read()
        
        # Size check (10MB limit)
        if len(content) > 10 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="File exceeds 10MB limit")
        
        with open(temp_path, "wb") as f:
            f.write(content)
        
        # Check cache
        sha256 = hashlib.sha256(content).hexdigest()
        cached = lookup_cache(sha256)
        if cached:
            return JSONResponse(content=cached)
        
        # Run analysis (synchronous — runs in thread pool via FastAPI)
        result = await asyncio.to_thread(run_analysis, temp_path)
        
        # Cache result
        store_result(sha256, file.filename, result)
        
        return JSONResponse(content=result)
    
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

@app.get("/analyze/image/{sha256}")
async def get_image(sha256: str):
    """Retrieve the PE grayscale byte visualization image for a given SHA256 hash."""
    img_b64 = get_cached_image(sha256)
    if not img_b64:
        raise HTTPException(status_code=404, detail="PE visualization image not found for the given hash.")
    try:
        img_bytes = base64.b64decode(img_b64)
        return Response(content=img_bytes, media_type="image/png")
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to decode PE visualization image.")

@app.post("/analyze/stream")
async def analyze_stream(file: UploadFile = File(...)):
    """Upload PE file, stream analysis steps via SSE, then send final report."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    if not file.filename.lower().endswith((".exe", ".dll")):
        raise HTTPException(status_code=400, detail="Only .exe and .dll files accepted")
    
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File exceeds 10MB limit")
    
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, f"{uuid.uuid4()}_{file.filename}")
    
    with open(temp_path, "wb") as f:
        f.write(content)
    
    # Check cache
    sha256 = hashlib.sha256(content).hexdigest()
    cached = lookup_cache(sha256)
    
    async def event_generator():
        try:
            if cached:
                sse_cached = cached.copy()
                sse_cached["steps"] = []
                for s in cached.get("steps", []):
                    sse_step = s.copy()
                    if sse_step.get("tool") == "visualize_pe" and isinstance(sse_step.get("result"), dict):
                        res = sse_step["result"].copy()
                        if "image_base64" in res:
                            res["image_base64"] = "<stream_placeholder>"
                        sse_step["result"] = res
                    sse_cached["steps"].append(sse_step)
                yield {"event": "cached", "data": json.dumps(sse_cached)}
                yield {"event": "done", "data": "{}"}
                return
            
            step_queue = asyncio.Queue()
            
            def on_step(step):
                sse_step = step.copy()
                if sse_step.get("tool") == "visualize_pe" and isinstance(sse_step.get("result"), dict):
                    res = sse_step["result"].copy()
                    if "image_base64" in res:
                        res["image_base64"] = "<stream_placeholder>"
                    sse_step["result"] = res
                asyncio.get_event_loop().call_soon_threadsafe(step_queue.put_nowait, sse_step)
            
            # Run analysis in background thread
            loop = asyncio.get_event_loop()
            analysis_task = loop.run_in_executor(None, run_analysis, temp_path, on_step)
            
            # Stream steps as they arrive
            while True:
                try:
                    step = await asyncio.wait_for(step_queue.get(), timeout=60.0)
                    yield {"event": "step", "data": json.dumps(step)}
                except asyncio.TimeoutError:
                    yield {"event": "heartbeat", "data": "{}"}
                
                if analysis_task.done():
                    # Drain remaining steps
                    while not step_queue.empty():
                        step = step_queue.get_nowait()
                        yield {"event": "step", "data": json.dumps(step)}
                    break
            
            # Get final result
            try:
                result = analysis_task.result()
                store_result(sha256, file.filename, result)
                
                sse_result = result.copy()
                sse_result["steps"] = []
                for s in result.get("steps", []):
                    sse_step = s.copy()
                    if sse_step.get("tool") == "visualize_pe" and isinstance(sse_step.get("result"), dict):
                        res = sse_step["result"].copy()
                        if "image_base64" in res:
                            res["image_base64"] = "<stream_placeholder>"
                        sse_step["result"] = res
                    sse_result["steps"].append(sse_step)
                yield {"event": "report", "data": json.dumps(sse_result)}
            except Exception as e:
                yield {"event": "error", "data": json.dumps({"error": str(e)})}
            
            yield {"event": "done", "data": "{}"}
        
        finally:
            # Cleanup temp file always
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
    
    return EventSourceResponse(event_generator())
