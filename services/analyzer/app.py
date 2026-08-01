"""
TENET AI - Analyzer Service
ML-based threat detection engine for LLM prompts.
"""
import os
import json
import asyncio
import sys
from datetime import datetime, timezone
from typing import Annotated, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header, Security
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import redis.asyncio as redis
try:
    import joblib
except ImportError:
    joblib = None  # type: ignore[assignment]

# Configure logging
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from services.utils.logging_config import setup_logging
from services.security import SecurityManager
from services.utils.metrics import PrometheusMiddleware, increment_detection
from prometheus_client import make_asgi_app
from services.analyzer.custom_rules import CustomRuleEngine

logger = setup_logging(__name__)

# Environment configuration
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8100))
MODEL_PATH = os.getenv("MODEL_PATH", "./models/trained")
PROMPT_INJECTION_THRESHOLD = float(os.getenv("PROMPT_INJECTION_THRESHOLD", 0.75))
SHUTDOWN_TIMEOUT = float(os.getenv("SHUTDOWN_TIMEOUT", 10.0))

# FastAPI app
app = FastAPI(
    title="TENET AI - Analyzer Service",
    description="ML-based threat detection for LLM applications",
    version="0.1.0"
)

# API Key Security Scheme for OpenAPI Docs
api_key_scheme = APIKeyHeader(
    name="x-api-key", 
    description="Enter your TENET AI API key to authenticate requests.",
    auto_error=False
)

# CORS middleware - configurable origins for security
CORS_ALLOWED_ORIGINS = os.getenv("CORS_ALLOWED_ORIGINS", "https://localhost:3000,https://localhost:5173")
allowed_origins = [origin.strip() for origin in CORS_ALLOWED_ORIGINS.split(",")]
app.add_middleware(PrometheusMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Global state
redis_client: Optional[redis.Redis] = None
ml_model = None
vectorizer = None
stop_event: Optional[asyncio.Event] = None
background_task = None

# Initialize custom dynamic rule engine
custom_engine = CustomRuleEngine()

security = SecurityManager(
    service_name="analyzer",
    redis_call=lambda coro: coro,
    redis_client_getter=lambda: None,
)


# Models
class ErrorResponse(BaseModel):
    """Standard error response schema."""
    detail: str = Field(..., description="Description of the error")

class AnalysisRequest(BaseModel):
    """Request for prompt analysis."""
    prompt: str = Field(..., description="The prompt to analyze", min_length=1, max_length=10000)
    context: Optional[str] = Field(None, description="Additional context", max_length=5000)


class AnalysisResponse(BaseModel):
    """Analysis result."""
    risk_score: float
    verdict: str
    threat_type: Optional[str] = None
    confidence: float
    details: dict


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    service: str
    version: str
    model_loaded: bool
    redis_connected: bool


def load_ml_models():
    """Load ML model and vectorizer from MODEL_PATH into global memory."""
    global ml_model, vectorizer
    if joblib is None:
        logger.warning("joblib is not installed; ML models cannot be loaded.")
        return False

    try:
        model_dir = Path(MODEL_PATH)
        model_file = model_dir / "prompt_detector.joblib"
        vectorizer_file = model_dir / "vectorizer.joblib"
        
        if model_file.exists() and vectorizer_file.exists():
            ml_model = joblib.load(model_file)
            vectorizer = joblib.load(vectorizer_file)
            logger.info("ML models loaded successfully")
            return True
        else:
            logger.warning(f"ML models not found at {MODEL_PATH}")
            return False
    except Exception:
        logger.exception("Failed to load ML models")
        return False


@app.on_event("startup")

async def startup():
    """Initialize connections and models on startup."""
    global redis_client, ml_model, vectorizer, background_task, stop_event
    
    # Connect to Redis
    try:
        redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            decode_responses=True
        )
        await redis_client.ping()
        logger.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
    except Exception:
        logger.exception("Failed to connect to Redis")
        redis_client = None
    
    # Load ML models
    load_ml_models()

    
    # Create stop event and start background processor
    stop_event = asyncio.Event()
    background_task = asyncio.create_task(process_event_queue())


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown."""
    global redis_client, stop_event, background_task
    
    # Signal the background task to stop
    if stop_event:
        stop_event.set()
        logger.info("Stop event set, waiting for background task to finish")
    
    # Wait for background task to complete gracefully
    if background_task:
        try:
            await asyncio.wait_for(background_task, timeout=SHUTDOWN_TIMEOUT)
            logger.info("Background task completed")
        except asyncio.TimeoutError:
            logger.warning("Background task did not complete in time, cancelling")
            background_task.cancel()
            try:
                await background_task
            except asyncio.CancelledError:
                logger.info("Background task cancelled successfully")

    # Close Redis connection
    if redis_client:
        try:
            await redis_client.close()
            logger.info("Redis connection closed")
        except Exception:
            logger.debug("Redis close failed during shutdown", exc_info=True)


@app.get(
    "/health", 
    response_model=HealthResponse,
    tags=["System"],
    summary="Service Health Check",
    description="Returns the current health status of the Analyzer service, including Redis and ML model connectivity."
)
async def health_check():
    """Health check endpoint."""
    redis_connected = False
    if redis_client:
        try:
            await redis_client.ping()
            redis_connected = True
        except Exception:
            logger.exception("Redis health check failed")
            redis_connected = False
    
    return HealthResponse(
        status="healthy" if redis_connected and ml_model else "degraded",
        service="analyzer",
        version="0.1.0",
        model_loaded=ml_model is not None,
        redis_connected=redis_connected
    )


@app.post(
    "/v1/analyze",
    response_model=AnalysisResponse,
    tags=["Analysis"],
    summary="Analyze Prompt",
    description="Analyzes a given prompt for security threats using both heuristic rules and ML-based detection. Requires a valid API key.",
    responses={
        401: {"model": ErrorResponse, "description": "Invalid API key"},
        403: {"model": ErrorResponse, "description": "Insufficient permissions"},
        429: {"model": ErrorResponse, "description": "Rate limit or quota exceeded"}
    },
    dependencies=[Security(api_key_scheme)]
)
async def analyze_prompt(
    request: AnalysisRequest,
    x_api_key: Annotated[str, Header(...)]
):
    """Analyze a prompt for security threats."""
    auth = await security.require_auth(x_api_key, required_permission="analyze")
    prompt = request.prompt
    result = run_analysis(prompt)
    
    increment_detection(service="analyzer", threat_type=result.threat_type, verdict=result.verdict)
    
    security.audit(
        action="analyze_prompt",
        result=result.verdict,
        context=auth,
        metadata={"risk_score": result.risk_score, "threat_type": result.threat_type},
    )
    return result


def run_analysis(prompt: str) -> AnalysisResponse:
    """Run full analysis on a prompt.

        Combines heuristic rule-based detection, custom YAML rules, and ML-based classification.
        Custom rules taking a 'BLOCKED' action receive top priority.
    """
    # 1. Run base heuristic analysis
    heuristic_result = heuristic_analysis(prompt)
    
    # 2. Run new custom YAML rule evaluation
    custom_result = custom_engine.evaluate(prompt)
    
    # 3. Run ML analysis (if model is loaded)
    ml_result = ml_analysis(prompt) if ml_model else None
    
    # Priority 1: Custom rule explicitly blocks the request
    if custom_result["recommended_action"] == "BLOCKED":
        trigger = custom_result["rule_hits"][0] if custom_result["rule_hits"] else {}
        return AnalysisResponse(
            risk_score=1.0,
            verdict="malicious",
            threat_type=trigger.get("rule_name", "custom_rule_block"),
            confidence=1.0,
            details={
                "method": "custom_heuristic",
                "matched_rules": custom_result["rule_hits"]
            }
        )
    
    # Priority 2: Standard heuristic flags high risk (> 0.8)
    if heuristic_result["risk_score"] > 0.8:
        return AnalysisResponse(
            risk_score=heuristic_result["risk_score"],
            verdict=heuristic_result["verdict"],
            threat_type=heuristic_result["threat_type"],
            confidence=0.95,
            details={
                "method": "heuristic",
                "matched_patterns": heuristic_result.get("patterns", [])
            }
        )
        
    # Priority 3: Custom rule flags the request for manual review
    if custom_result["recommended_action"] == "FLAGGED":
        trigger = custom_result["rule_hits"][0] if custom_result["rule_hits"] else {}
        return AnalysisResponse(
            risk_score=0.75,
            verdict="suspicious",
            threat_type=trigger.get("rule_name", "custom_rule_flag"),
            confidence=0.90,
            details={
                "method": "custom_heuristic",
                "matched_rules": custom_result["rule_hits"]
            }
        )
        
    # Priority 4: ML model flags high risk
    if ml_result and ml_result["risk_score"] > PROMPT_INJECTION_THRESHOLD:
        return AnalysisResponse(
            risk_score=ml_result["risk_score"],
            verdict=ml_result["verdict"],
            threat_type=ml_result["threat_type"],
            confidence=ml_result["confidence"],
            details={"method": "ml", "model_version": "0.1"}
        )
        
    # Priority 5: Standard heuristic suspect range (> 0.5)
    if heuristic_result["risk_score"] > 0.5:
        return AnalysisResponse(
            risk_score=heuristic_result["risk_score"],
            verdict="suspicious",
            threat_type=heuristic_result["threat_type"],
            confidence=0.6,
            details={"method": "heuristic", "recommendation": "manual_review"}
        )
        
    # Priority 6: ML model suspect range (> 0.5)
    if ml_result and ml_result["risk_score"] > 0.5:
        return AnalysisResponse(
            risk_score=ml_result["risk_score"],
            verdict="suspicious",
            threat_type=ml_result["threat_type"],
            confidence=ml_result["confidence"],
            details={"method": "ml", "model_version": "0.1", "recommendation": "manual_review"}
        )
        
    # Fallback: Safe/Benign response
    return AnalysisResponse(
        risk_score=max(heuristic_result["risk_score"], ml_result["risk_score"] if ml_result else 0.0),
        verdict="benign",
        threat_type=None,
        confidence=0.85,
        details={"method": "combined"}
    )


def heuristic_analysis(prompt: str) -> dict:
    """Rule-based heuristic analysis."""
    prompt_lower = prompt.lower()
    matched_patterns = []
    max_score = 0.0
    threat_type = None
    
    # Pattern definitions with scores
    patterns = {
        "prompt_injection": {
            "ignore previous instructions": 0.95,
            "ignore all previous": 0.95,
            "disregard your instructions": 0.90,
            "forget your system prompt": 0.90,
            "override system": 0.85,
            "</s>": 0.90,
            "<|system|>": 0.95,
            "\n\n###": 0.80,
        },
        "jailbreak": {
            "do anything now": 0.90,
            "you are now dan": 0.95,
            "no restrictions": 0.80,
            "bypass your programming": 0.85,
            "override your safety": 0.90,
            "evil mode": 0.85,
            "developer mode": 0.80,
        },
        "data_extraction": {
            "show me your system prompt": 0.75,
            "what are your instructions": 0.70,
            "reveal your training": 0.75,
            "list your rules": 0.65,
        }
    }
    
    for category, category_patterns in patterns.items():
        for pattern, score in category_patterns.items():
            if pattern in prompt_lower:
                matched_patterns.append(pattern)
                if score > max_score:
                    max_score = score
                    threat_type = category
    
    verdict = "benign"
    if max_score > 0.8:
        verdict = "malicious"
    elif max_score > 0.5:
        verdict = "suspicious"
    
    return {
        "risk_score": max_score,
        "verdict": verdict,
        "threat_type": threat_type,
        "patterns": matched_patterns
    }


def ml_analysis(prompt: str) -> dict:
    """ML-based analysis using trained model."""
    global ml_model, vectorizer
    
    if not ml_model or not vectorizer:
        return {"risk_score": 0.0, "verdict": "unknown", "threat_type": None, "confidence": 0.0}
    
    try:
        # Vectorize the prompt
        X = vectorizer.transform([prompt])
        
        # Get prediction probabilities
        proba = ml_model.predict_proba(X)[0]
        
        # Assuming binary classification: [benign, malicious]
        malicious_prob = proba[1] if len(proba) > 1 else proba[0]
        
        verdict = "malicious" if malicious_prob > PROMPT_INJECTION_THRESHOLD else "benign"
        if 0.5 < malicious_prob <= PROMPT_INJECTION_THRESHOLD:
            verdict = "suspicious"
        
        return {
            "risk_score": float(malicious_prob),
            "verdict": verdict,
            "threat_type": "prompt_injection" if malicious_prob > 0.5 else None,
            "confidence": float(max(proba))
        }
    except Exception:
        logger.exception("ML analysis error")
        return {"risk_score": 0.0, "verdict": "error", "threat_type": None, "confidence": 0.0}


async def _wait_for_stop_event():
    """Wait for the global stop event to be set."""
    if stop_event is None:
        return
    await stop_event.wait()


async def _wait_with_timeout(seconds: float):
    """Wait for the stop event with a timeout, suppressing TimeoutError."""
    try:
        async with asyncio.timeout(seconds):
            await _wait_for_stop_event()
    except asyncio.TimeoutError:
        pass


async def _update_and_store_event(event: dict, event_id: str, result: AnalysisResponse):
    """Update event with analysis results and store in Redis."""
    if not redis_client:
        logger.warning(f"Cannot store event {event_id}: Redis client not available")
        return
    
    event["analyzed"] = True
    event["risk_score"] = result.risk_score
    event["verdict"] = result.verdict
    event["threat_type"] = result.threat_type
    event["analysis_details"] = result.details
    event["analyzed_at"] = datetime.now(timezone.utc).isoformat()
    
    await redis_client.set(
        f"tenet:event:{event_id}",
        json.dumps(event),
        ex=86400
    )
    
    if result.verdict == "malicious":
        await redis_client.lpush("tenet:alerts", json.dumps(event))
        logger.warning(f"Alert: Malicious event detected - {event_id}")


async def _process_single_event(event_json: str):
    """Process a single event from the queue."""
    try:
        event = json.loads(event_json)
    except json.JSONDecodeError:
        logger.exception("Failed to parse event JSON")
        return
    
    if not isinstance(event, dict):
        logger.warning("Event is not a dictionary, skipping")
        return
    
    event_id = event.get('event_id')
    if not event_id or not isinstance(event_id, str):
        safe_summary = {
            "user_id": event.get('user_id'),
            "timestamp": event.get('timestamp'),
            "has_prompt": 'prompt' in event,
            "prompt_length": len(event.get('prompt', '')) if isinstance(event.get('prompt'), str) else 0
        }
        logger.warning(f"Skipping event without valid event_id. Safe metadata: {safe_summary}")
        return
    
    event_id = event_id.strip()
    if not event_id:
        logger.warning("Skipping event with empty event_id after stripping")
        return
    
    if len(event_id) > 255:
        logger.warning(f"Skipping event with overly long event_id ({len(event_id)} chars)")
        return
    
    logger.info(f"Processing event: {event_id}")
    
    prompt = event.get("prompt", "")
    if not isinstance(prompt, str):
        logger.warning(f"Event {event_id} has invalid prompt type, skipping")
        return
    
    if not prompt.strip():
        logger.warning(f"Event {event_id} has empty prompt, skipping")
        return
    
    if len(prompt) > 10000:
        logger.warning(f"Event {event_id} has overly long prompt ({len(prompt)} chars), truncating")
        prompt = prompt[:10000]
    
    result = run_analysis(prompt)
    
    increment_detection(service="analyzer_bg", threat_type=result.threat_type, verdict=result.verdict)
    await _update_and_store_event(event, event_id, result)


async def process_event_queue():
    """Background task to process events from the Redis queue."""
    global stop_event, redis_client
    
    while not stop_event.is_set():
        try:
            if not redis_client:
                await _wait_with_timeout(5.0)
                continue
            
            event_json = await redis_client.rpop("tenet:events:queue")
            
            if event_json:
                await _process_single_event(event_json)
            else:
                await _wait_with_timeout(1.0)
                
        except Exception:
            logger.exception("Queue processing error")
            await _wait_with_timeout(5.0)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)