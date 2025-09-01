import orjson
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel

# Add project root to path to allow imports from other modules
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detector.config import ConfigLoader
from detector.event_model import Event
from worker.llm_client import OllamaClient
from worker.prompts import SINGLE_EVENT_ANALYSIS_PROMPT

# --- Configuration ---
try:
    config = ConfigLoader()
    api_config = config.get_api_config()
    worker_config = config.get_worker_config()
    events_dir = Path("clearwatch") / config.get("events.dir", "events")
except Exception as e:
    logging.basicConfig()
    logging.error(f"Failed to load configuration for API server: {e}")
    sys.exit(1)

# --- FastAPI App Initialization ---
app = FastAPI(
    title="Clearwatch API",
    description="API for querying security events and getting LLM-powered analysis.",
    version="0.1.0",
)

# --- LLM Client Initialization ---
llm_client: Optional[OllamaClient] = None
if api_config.get("enabled", False) and worker_config.get("enabled", False):
    try:
        llm_client = OllamaClient(model=worker_config.get("model"))
    except Exception as e:
        logging.warning(f"Could not initialize OllamaClient: {e}")


# --- Pydantic Models ---
class AlertExplanationRequest(BaseModel):
    event: Dict[str, Any]

class ErrorResponse(BaseModel):
    detail: str


# --- Helper Functions ---
def read_recent_events(limit: int) -> List[Dict[str, Any]]:
    """Reads the most recent events from .jsonl files."""
    events = []
    if not events_dir.exists():
        return []

    # Get all event files, sorted by modification time (newest first)
    try:
        event_files = sorted(events_dir.glob("*.jsonl"), key=os.path.getmtime, reverse=True)
    except Exception:
        return [] # In case of race condition where a file is deleted during sort

    for file_path in event_files:
        if len(events) >= limit:
            break
        try:
            with open(file_path, "rb") as f:
                lines = f.readlines()
                # Read lines from the end of the file to get the most recent events first
                for line in reversed(lines):
                    if len(events) >= limit:
                        break
                    try:
                        events.append(orjson.loads(line))
                    except orjson.JSONDecodeError:
                        continue
        except IOError:
            continue
            
    return events[:limit]


# --- API Endpoints ---
@app.get(
    "/alerts/recent",
    response_model=List[Dict[str, Any]],
    summary="Get Recent Security Alerts",
    description="Returns a list of the most recent security events detected, sorted from newest to oldest.",
)
async def get_recent_alerts(limit: int = 100):
    """
    Retrieves the most recent security alerts.

    - **limit**: The maximum number of alerts to return.
    """
    if not api_config.get("enabled", False):
        raise HTTPException(status_code=404, detail="API is not enabled in the configuration.")
        
    try:
        recent_events = read_recent_events(limit)
        return recent_events
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read event files: {e}")


@app.post(
    "/alerts/explain",
    response_model=str,
    summary="Explain a Security Alert",
    description="Receives a security event and uses a local LLM to provide an analysis, including impact, triage steps, and remediation advice.",
    responses={
        400: {"model": ErrorResponse, "description": "Invalid event format"},
        503: {"model": ErrorResponse, "description": "LLM service is unavailable or disabled"},
    },
)
async def explain_alert(request: AlertExplanationRequest):
    """
    Provides an LLM-powered explanation for a given security event.
    """
    if not api_config.get("enabled", False) or not llm_client:
        raise HTTPException(status_code=503, detail="LLM analysis is not enabled in the configuration.")

    # Validate the event structure using our Pydantic model
    try:
        Event.model_validate(request.event)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid event data provided: {e}")

    # Check if LLM is available
    if not llm_client.is_available():
        raise HTTPException(status_code=503, detail="The Ollama LLM service is currently unavailable.")

    # Generate the explanation
    explanation = llm_client.ask_single_event(
        event=request.event,
        prompt_template=SINGLE_EVENT_ANALYSIS_PROMPT
    )

    if not explanation:
        raise HTTPException(status_code=500, detail="Failed to get a valid response from the LLM.")

    return explanation

# --- Root Endpoint ---
@app.get("/", summary="API Status")
async def root():
    return {"status": "running", "title": "Clearwatch API"}

# --- Uvicorn Runner ---
if __name__ == "__main__":
    import uvicorn
    if api_config.get("enabled", False):
        host = api_config.get("host", "127.0.0.1")
        port = api_config.get("port", 8088)
        print(f"Starting Clearwatch API server on http://{host}:{port}")
        uvicorn.run(app, host=host, port=port)
    else:
        print("API server is disabled in the configuration. Exiting.")
