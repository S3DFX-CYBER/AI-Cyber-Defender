"""
TENET AI - Analyzer Service
ML-based threat detection engine for LLM prompts.
"""
import os
import re
import json
import asyncio
import sys
from datetime import datetime, timezone
from typing import Annotated, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import redis.asyncio as redis
try:
    import joblib
except ImportError:
    joblib = None  # type: ignore[assignment]

try:
    from langdetect import detect as _langdetect_detect
    from langdetect.lang_detect_exception import LangDetectException
except ImportError:  # pragma: no cover
    _langdetect_detect = None  # type: ignore[assignment]
    LangDetectException = Exception  # type: ignore[misc,assignment]

# Configure logging
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from services.utils.logging_config import setup_logging
from services.security import SecurityManager
from services.utils.metrics import PrometheusMiddleware, increment_detection
from prometheus_client import make_asgi_app
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
security = SecurityManager(
    service_name="analyzer",
    redis_call=lambda coro: coro,
    redis_client_getter=lambda: None,
)


# Models
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
    detected_language: Optional[str] = Field(None, description="ISO 639-1 language code detected in prompt")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    service: str
    version: str
    model_loaded: bool
    redis_connected: bool


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
    try:
        model_dir = Path(MODEL_PATH)
        model_file = model_dir / "prompt_detector.joblib"
        vectorizer_file = model_dir / "vectorizer.joblib"
        
        if model_file.exists() and vectorizer_file.exists():
            ml_model = joblib.load(model_file)
            vectorizer = joblib.load(vectorizer_file)
            logger.info("ML models loaded successfully")
        else:
            logger.warning(f"ML models not found at {MODEL_PATH}")
    except Exception:
        logger.exception("Failed to load ML models")
    
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
            except asyncio.CancelledError:  # NOSONAR - Don't re-raise in shutdown handler, cancellation is expected
                logger.info("Background task cancelled successfully")

    # Close Redis connection
    if redis_client:
        try:
            await redis_client.close()
            logger.info("Redis connection closed")
        except Exception:
            logger.debug("Redis close failed during shutdown", exc_info=True)


@app.get("/health", response_model=HealthResponse)
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
    responses={
        401: {"description": "Invalid API key"},
        403: {"description": "Insufficient permissions"},
        429: {"description": "Rate limit or quota exceeded"}
    }
)
async def analyze_prompt(
    request: AnalysisRequest,
    x_api_key: Annotated[str, Header(...)]
):
    """
    Analyze a prompt for security threats.
    Uses both heuristic rules and ML-based detection.
    """
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


def detect_language(prompt: str) -> Optional[str]:
    """Detect the language of a prompt.

    Args:
        prompt: The user's input prompt.

    Returns:
        ISO 639-1 language code (e.g. 'en', 'es', 'fr') or None if detection fails.
        Note: langdetect may return sub-codes like 'zh-cn'; these are normalized to
        the primary tag (e.g. 'zh') to conform to the ISO 639-1 contract.
    """
    if _langdetect_detect is None:
        return None
    try:
        detected = _langdetect_detect(prompt)
        if not detected:
            return None
        # Normalize sub-tags (e.g. 'zh-cn', 'zh-tw') → primary ISO 639-1 code ('zh')
        return detected.split("-", 1)[0].lower()
    except LangDetectException:
        logger.debug("Language detection failed for prompt (too short or ambiguous)")
        return None


def _pattern_match(pattern: str, text: str) -> bool:
    """Match a pattern in text with word-boundary enforcement.

    Patterns that start or end on a word character are wrapped with ``\\b``
    anchors so that a short pattern like ``'tu es dan'`` does not falsely
    match ``'tu es dans quel pays'`` or ``'du bist dankbar'``.

    Patterns that begin/end with non-word characters (e.g. ``'</s>'``,
    ``'<|system|>'``) fall back to plain substring matching because regex
    word-boundaries are meaningless at non-word edges.

    Args:
        pattern: The (already lowercased) pattern string to look for.
        text: The (already lowercased) prompt text to search in.

    Returns:
        True if the pattern is found in text respecting word boundaries.
    """
    if not pattern:
        return False
        
    # CJK languages don't use spaces for word boundaries, so regex \b fails
    # on partial matches. For CJK, plain substring matching is accurate enough.
    if re.search(r'[\u4e00-\u9fff]', pattern):
        return pattern in text

    starts_word = bool(re.match(r'^\w', pattern))
    ends_word = bool(re.search(r'\w$', pattern))
    if starts_word or ends_word:
        prefix = r'\b' if starts_word else ''
        suffix = r'\b' if ends_word else ''
        try:
            return bool(re.search(prefix + re.escape(pattern) + suffix, text))
        except re.error:
            pass
    return pattern in text


def run_analysis(prompt: str) -> AnalysisResponse:
    """Run full analysis on a prompt."""
    # Language detection preprocessing
    language = detect_language(prompt)
    if language:
        logger.debug(f"Detected prompt language: {language}")

    # Heuristic analysis
    heuristic_result = heuristic_analysis(prompt)

    # ML analysis (if model is loaded)
    ml_result = ml_analysis(prompt) if ml_model else None

    # Combine results
    if heuristic_result["risk_score"] > 0.8:
        return AnalysisResponse(
            risk_score=heuristic_result["risk_score"],
            verdict=heuristic_result["verdict"],
            threat_type=heuristic_result["threat_type"],
            confidence=0.95,
            detected_language=language,
            details={
                "method": "heuristic",
                "matched_patterns": heuristic_result.get("patterns", [])
            }
        )
    elif ml_result and ml_result["risk_score"] > PROMPT_INJECTION_THRESHOLD:
        return AnalysisResponse(
            risk_score=ml_result["risk_score"],
            verdict=ml_result["verdict"],
            threat_type=ml_result["threat_type"],
            confidence=ml_result["confidence"],
            detected_language=language,
            details={"method": "ml", "model_version": "0.1"}
        )
    elif heuristic_result["risk_score"] > 0.5:
        return AnalysisResponse(
            risk_score=heuristic_result["risk_score"],
            verdict="suspicious",
            threat_type=heuristic_result["threat_type"],
            confidence=0.6,
            detected_language=language,
            details={"method": "heuristic", "recommendation": "manual_review"}
        )
    elif ml_result and ml_result["risk_score"] > 0.5:
        return AnalysisResponse(
            risk_score=ml_result["risk_score"],
            verdict="suspicious",
            threat_type=ml_result["threat_type"],
            confidence=ml_result["confidence"],
            detected_language=language,
            details={"method": "ml", "model_version": "0.1", "recommendation": "manual_review"}
        )
    else:
        return AnalysisResponse(
            risk_score=max(heuristic_result["risk_score"], ml_result["risk_score"] if ml_result else 0.0),
            verdict="benign",
            threat_type=None,
            confidence=0.85,
            detected_language=language,
            details={"method": "combined"}
        )


def heuristic_analysis(prompt: str) -> dict:
    """Rule-based heuristic analysis supporting English and 5 additional languages.

    Supported languages: English (en), Spanish (es), French (fr),
    German (de), Chinese (zh), Arabic (ar).
    """
    prompt_lower = prompt.lower()
    matched_patterns = []
    max_score = 0.0
    threat_type = None

    # Pattern definitions with scores
    # Each entry: pattern_string -> risk_score
    # Patterns are lowercased for case-insensitive matching.
    patterns: dict[str, dict[str, float]] = {
        "prompt_injection": {
            # --- English ---
            "ignore previous instructions": 0.95,
            "ignore all previous": 0.95,
            "disregard your instructions": 0.90,
            "forget your system prompt": 0.90,
            "override system": 0.85,
            "</s>": 0.90,
            "<|system|>": 0.95,
            "\n\n###": 0.80,
            # --- Spanish (es) ---
            "ignora las instrucciones anteriores": 0.95,
            "ignora todas las instrucciones previas": 0.95,
            "olvida tus instrucciones": 0.90,
            "ignora tu prompt de sistema": 0.90,
            "anula el sistema": 0.85,
            # --- French (fr) ---
            "ignore les instructions précédentes": 0.95,
            "ignore toutes les instructions": 0.95,
            "oublie tes instructions": 0.90,
            "oublie ton prompt système": 0.90,
            "remplace le système": 0.85,
            # --- German (de) ---
            "ignoriere vorherige anweisungen": 0.95,
            "ignoriere alle vorherigen anweisungen": 0.95,
            "vergiss deine anweisungen": 0.90,
            "vergiss deinen system-prompt": 0.90,
            "überschreibe das system": 0.85,
            # --- Chinese (zh) ---
            "忽略之前的指令": 0.95,
            "忽略所有先前的指令": 0.95,
            "忘记你的指令": 0.90,
            "忘记你的系统提示": 0.90,
            "覆盖系统": 0.85,
            # --- Arabic (ar) ---
            "تجاهل التعليمات السابقة": 0.95,
            "تجاهل جميع التعليمات": 0.95,
            "انسَ تعليماتك": 0.90,
            "انسَ موجه النظام": 0.90,
            "تجاوز النظام": 0.85,
        },
        "jailbreak": {
            # --- English ---
            "do anything now": 0.90,
            "you are now dan": 0.95,
            "no restrictions": 0.80,
            "bypass your programming": 0.85,
            "override your safety": 0.90,
            "evil mode": 0.85,
            "developer mode": 0.80,
            # --- Spanish (es) ---
            "eres dan": 0.95,
            "ahora eres dan": 0.95,
            "sin restricciones": 0.80,
            "modo desarrollador": 0.80,
            "modo maligno": 0.85,
            # --- French (fr) ---
            "tu es dan": 0.95,
            "tu es maintenant dan": 0.95,
            "sans restrictions": 0.80,
            "mode développeur": 0.80,
            "mode maléfique": 0.85,
            # --- German (de) ---
            "du bist dan": 0.95,
            "du bist jetzt dan": 0.95,
            "keine einschränkungen": 0.80,
            "entwicklermodus": 0.80,
            "böser modus": 0.85,
            # --- Chinese (zh) ---
            "你现在是dan": 0.95,
            "你是dan": 0.95,
            "没有限制": 0.80,
            "开发者模式": 0.80,
            "邪恶模式": 0.85,
            # --- Arabic (ar) ---
            "أنت الآن دان": 0.95,
            "أنت دان": 0.95,
            "بدون قيود": 0.80,
            "وضع المطور": 0.80,
            "الوضع الشرير": 0.85,
        },
        "data_extraction": {
            # --- English ---
            "show me your system prompt": 0.75,
            "what are your instructions": 0.70,
            "reveal your training": 0.75,
            "list your rules": 0.65,
            # --- Spanish (es) ---
            "muéstrame tu prompt de sistema": 0.75,
            "cuáles son tus instrucciones": 0.70,
            "revela tu entrenamiento": 0.75,
            "lista tus reglas": 0.65,
            # --- French (fr) ---
            "montre-moi ton prompt système": 0.75,
            "quelles sont tes instructions": 0.70,
            "révèle ton entraînement": 0.75,
            "liste tes règles": 0.65,
            # --- German (de) ---
            "zeig mir deinen system-prompt": 0.75,
            "was sind deine anweisungen": 0.70,
            "enthülle dein training": 0.75,
            "liste deine regeln": 0.65,
            # --- Chinese (zh) ---
            "显示你的系统提示": 0.75,
            "你的指令是什么": 0.70,
            "揭示你的训练数据": 0.75,
            "列出你的规则": 0.65,
            # --- Arabic (ar) ---
            "أرني موجه النظام": 0.75,
            "ما هي تعليماتك": 0.70,
            "اكشف عن بياناتك التدريبية": 0.75,
            "اسرد قواعدك": 0.65,
        }
    }

    for category, category_patterns in patterns.items():
        for pattern, score in category_patterns.items():
            if _pattern_match(pattern, prompt_lower):
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
    """Helper to wait for stop event. Use with asyncio.timeout() context manager."""
    # Defensive check: ensure stop_event exists before awaiting
    if stop_event is None:
        return
    await stop_event.wait()


async def _wait_with_timeout(seconds: float):
    """Wait for stop event with timeout, suppressing TimeoutError."""
    try:
        async with asyncio.timeout(seconds):
            await _wait_for_stop_event()
    except asyncio.TimeoutError:
        pass


async def _update_and_store_event(event: dict, event_id: str, result: AnalysisResponse):
    """Update event with analysis results and store in Redis."""
    # Ensure redis_client is available
    if not redis_client:
        logger.warning(f"Cannot store event {event_id}: Redis client not available")
        return
    
    # Update the event with analysis results
    event["analyzed"] = True
    event["risk_score"] = result.risk_score
    event["verdict"] = result.verdict
    event["threat_type"] = result.threat_type
    event["analysis_details"] = result.details
    event["analyzed_at"] = datetime.now(timezone.utc).isoformat()
    
    # Store updated event
    await redis_client.set(
        f"tenet:event:{event_id}",
        json.dumps(event),
        ex=86400
    )
    
    # If malicious, add to alerts
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
    
    # Validate event structure
    if not isinstance(event, dict):
        logger.warning("Event is not a dictionary, skipping")
        return
    
    # Validate event_id presence and format
    event_id = event.get('event_id')
    if not event_id or not isinstance(event_id, str):
        # Log only safe metadata, avoid exposing sensitive prompts
        safe_summary = {
            "user_id": event.get('user_id'),
            "timestamp": event.get('timestamp'),
            "has_prompt": 'prompt' in event,
            "prompt_length": len(event.get('prompt', '')) if isinstance(event.get('prompt'), str) else 0
        }
        logger.warning(f"Skipping event without valid event_id. Safe metadata: {safe_summary}")
        return
    
    # Additional event_id validation
    event_id = event_id.strip()
    if not event_id:
        logger.warning("Skipping event with empty event_id after stripping")
        return
    
    if len(event_id) > 255:
        logger.warning(f"Skipping event with overly long event_id ({len(event_id)} chars)")
        return
    
    logger.info(f"Processing event: {event_id}")
    
    # Get and validate prompt
    prompt = event.get("prompt", "")
    if not isinstance(prompt, str):
        logger.warning(f"Event {event_id} has invalid prompt type, skipping")
        return
    
    if not prompt.strip():
        logger.warning(f"Event {event_id} has empty prompt, skipping")
        return
    
    # Truncate very long prompts for safety
    if len(prompt) > 10000:
        logger.warning(f"Event {event_id} has overly long prompt ({len(prompt)} chars), truncating")
        prompt = prompt[:10000]
    
    # Analyze the prompt
    result = run_analysis(prompt)
    
    increment_detection(service="analyzer_bg", threat_type=result.threat_type, verdict=result.verdict)
    
    # Update and store event
    await _update_and_store_event(event, event_id, result)


async def process_event_queue():
    """Background task to process events from the queue."""
    global stop_event, redis_client
    
    while not stop_event.is_set():
        try:
            if not redis_client:
                await _wait_with_timeout(5.0)
                continue
            
            # Pop event from queue
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
