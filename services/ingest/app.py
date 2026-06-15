"""
TENET AI - Ingest Service
Middleware layer for intercepting and processing LLM requests.

Production hardening:
- Circuit breaker for Redis (prevents cascade failures)
- Graceful degradation (service continues when Redis is unavailable)
- Request timeouts on all Redis calls
- Structured JSON logging
- Background Redis reconnect loop
"""

import asyncio
import json
import logging
import os
import signal
import time
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

import redis.asyncio as redis
from fastapi import FastAPI, Header, HTTPException, Query

from services.security import SecurityManager
from services.utils.metrics import PrometheusMiddleware, increment_detection
from prometheus_client import make_asgi_app
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


class JSONFormatter(logging.Formatter):
    """Emit logs in structured JSON format."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": f"{datetime.utcnow().isoformat()}Z",
            "level": record.levelname,
            "service": "tenet-ingest",
            "version": "0.1.0",
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger(__name__)


REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_TIMEOUT_S = float(os.getenv("REDIS_TIMEOUT_S", 2.0))
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8000))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

CB_FAILURE_THRESHOLD = int(os.getenv("CB_FAILURE_THRESHOLD", 3))
CB_RECOVERY_TIMEOUT_S = float(os.getenv("CB_RECOVERY_TIMEOUT_S", 30.0))
CB_HALF_OPEN_MAX_CALLS = int(os.getenv("CB_HALF_OPEN_MAX_CALLS", 1))


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Lightweight circuit breaker for Redis calls."""

    def __init__(
        self,
        name: str,
        failure_threshold: int = CB_FAILURE_THRESHOLD,
        recovery_timeout: float = CB_RECOVERY_TIMEOUT_S,
        half_open_max_calls: int = CB_HALF_OPEN_MAX_CALLS,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_ts = 0.0
        self._half_open_calls = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    def allow_request(self) -> bool:
        if self._state == CircuitState.CLOSED:
            return True

        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_ts >= self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
                logger.info("Circuit breaker [%s] -> HALF_OPEN", self.name)
                return True
            return False

        if self._state == CircuitState.HALF_OPEN:
            if self._half_open_calls < self.half_open_max_calls:
                self._half_open_calls += 1
                return True
            return False

        return False

    async def record_success(self) -> None:
        async with self._lock:
            self._failure_count = 0
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.CLOSED
                self._half_open_calls = 0
                logger.info("Circuit breaker [%s] -> CLOSED", self.name)

    async def record_failure(self) -> None:
        async with self._lock:
            self._failure_count += 1
            self._last_failure_ts = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                logger.error("Circuit breaker [%s] -> OPEN (probe failed)", self.name)
                return

            if self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                logger.error("Circuit breaker [%s] -> OPEN (%s failures)", self.name, self._failure_count)


app = FastAPI(
    title="TENET AI - Ingest Service",
    description="Security middleware for LLM applications",
    version="0.1.0",
)

app.add_middleware(PrometheusMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

redis_client: Optional[redis.Redis] = None
redis_cb = CircuitBreaker("redis-ingest")
_shutdown_event = asyncio.Event()
_start_time = time.monotonic()
security = SecurityManager(
    service_name="ingest",
    redis_call=lambda coro: redis_call(coro),
    redis_client_getter=lambda: redis_client,
)


class LLMEventRequest(BaseModel):
    source_type: str = Field(..., description="chat | agent | api | workflow", min_length=1, max_length=64)
    source_id: str = Field(..., description="Unique identifier for the source", min_length=1, max_length=128)
    model: str = Field(..., description="LLM model being used", min_length=1, max_length=128)
    prompt: str = Field(..., description="The prompt to analyze", min_length=1, max_length=10000)
    system_prompt: Optional[str] = Field(None)
    metadata: Optional[dict[str, Any]] = Field(default_factory=dict)


class LLMEventResponse(BaseModel):
    event_id: str
    timestamp: str
    blocked: bool = False
    sanitized: bool = False
    risk_score: float = 0.0
    verdict: str = "pending"
    message: str = "Event queued for analysis"
    degraded: bool = False


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    redis_connected: bool
    circuit_state: str
    uptime_seconds: float


class EventDetailResponse(BaseModel):
    event_id: str
    timestamp: str
    source_type: str
    source_id: str
    model: str
    prompt: str
    system_prompt: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None
    blocked: bool
    risk_score: float
    verdict: str


async def redis_call(coro):
    """Execute a Redis coroutine behind timeout + circuit breaker guards."""
    if not redis_client or not redis_cb.allow_request():
        return None

    try:
        result = await asyncio.wait_for(coro, timeout=REDIS_TIMEOUT_S)
        await redis_cb.record_success()
        return result
    except asyncio.TimeoutError:
        logger.warning("Redis call timed out after %ss", REDIS_TIMEOUT_S)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Redis call failed: %s", exc)

    await redis_cb.record_failure()
    return None


@app.on_event("startup")
async def startup() -> None:
    global redis_client

    try:
        redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            decode_responses=True,
            socket_connect_timeout=REDIS_TIMEOUT_S,
            socket_timeout=REDIS_TIMEOUT_S,
            retry_on_timeout=False,
        )
        await asyncio.wait_for(redis_client.ping(), timeout=REDIS_TIMEOUT_S)
        logger.info("Connected to Redis at %s:%s", REDIS_HOST, REDIS_PORT)
    except Exception as exc:  # noqa: BLE001
        logger.error("Redis unavailable at startup (%s); running in degraded mode", exc)
        redis_client = None

    asyncio.create_task(_redis_reconnect_loop())

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            asyncio.get_running_loop().add_signal_handler(sig, _shutdown_event.set)
        except NotImplementedError:
            pass


@app.on_event("shutdown")
async def shutdown() -> None:
    global redis_client

    _shutdown_event.set()
    if redis_client:
        try:
            await redis_client.close()
        except Exception:  # noqa: BLE001
            pass
        logger.info("Redis connection closed")


async def _redis_reconnect_loop() -> None:
    global redis_client

    while not _shutdown_event.is_set():
        await asyncio.sleep(CB_RECOVERY_TIMEOUT_S)
        if redis_cb.state == CircuitState.CLOSED:
            continue

        try:
            if redis_client is None:
                redis_client = redis.Redis(
                    host=REDIS_HOST,
                    port=REDIS_PORT,
                    decode_responses=True,
                    socket_connect_timeout=REDIS_TIMEOUT_S,
                    socket_timeout=REDIS_TIMEOUT_S,
                    retry_on_timeout=False,
                )
            await asyncio.wait_for(redis_client.ping(), timeout=REDIS_TIMEOUT_S)
            await redis_cb.record_success()
            logger.info("Redis reconnection probe succeeded")
        except Exception as exc:  # noqa: BLE001
            logger.debug("Redis reconnection probe failed: %s", exc)
            await redis_cb.record_failure()


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    redis_ok = await redis_call(redis_client.ping()) if redis_client else None

    return HealthResponse(
        status="healthy" if redis_ok else "degraded",
        service="ingest",
        version="0.1.0",
        redis_connected=bool(redis_ok),
        circuit_state=redis_cb.state.value,
        uptime_seconds=round(time.monotonic() - _start_time, 1),
    )


@app.post("/v1/events/llm", response_model=LLMEventResponse)
async def ingest_llm_event(request: LLMEventRequest, x_api_key: str = Header(...)):
    auth = await security.require_auth(x_api_key, required_permission="ingest")
    if not request.prompt.strip():
        raise HTTPException(status_code=422, detail="Prompt must not be empty or whitespace")

    event_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()
    blocked, risk_score, verdict, threat_type = quick_heuristic_check(request.prompt)
    
    increment_detection(service="ingest", threat_type=threat_type, verdict=verdict)

    event_payload = {
        "event_id": event_id,
        "timestamp": timestamp,
        "source_type": request.source_type,
        "source_id": request.source_id,
        "model": request.model,
        "prompt": request.prompt,
        "system_prompt": request.system_prompt,
        "metadata": request.metadata,
        "org_id": auth.org_id,
        "api_key_id": auth.key_id,
        "blocked": blocked,
        "risk_score": risk_score,
        "verdict": verdict,
    }

    degraded = False
    if not blocked:
        queued = await redis_call(redis_client.lpush("tenet:events:queue", json.dumps(event_payload))) if redis_client else None
        stored = await redis_call(redis_client.set(f"tenet:event:{event_id}", json.dumps(event_payload), ex=86400)) if redis_client else None

        if not queued or not stored:
            degraded = True
            logger.warning("Event %s processed in degraded mode (not persisted)", event_id)

    security.audit(
        action="ingest_event",
        result=verdict,
        context=auth,
        metadata={"event_id": event_id, "blocked": blocked, "risk_score": risk_score},
    )

    return LLMEventResponse(
        event_id=event_id,
        timestamp=timestamp,
        blocked=blocked,
        risk_score=risk_score,
        verdict=verdict,
        message="Blocked - malicious pattern detected" if blocked else "Event queued for analysis",
        degraded=degraded,
    )


def quick_heuristic_check(prompt: str) -> tuple[bool, float, str, str]:
    prompt_lower = prompt.lower()

    injection_patterns = [
        "ignore previous instructions",
        "ignore all previous",
        "disregard your instructions",
        "forget your system prompt",
        "you are now",
        "from now on you are",
        "new persona:",
        "jailbreak mode",
        "dan mode",
        "developer mode enabled",
        "simulate being",
        "</s>",
        "<|system|>",
        "system prompt:",
        "reveal your instructions",
    ]

    jailbreak_patterns = [
        "do anything now",
        "no restrictions",
        "without any limitations",
        "bypass your programming",
        "override your safety",
        "pretend you have no rules",
        "act as an unrestricted ai",
        "evil mode",
        "chaos mode",
    ]

    extraction_patterns = [
        "show me your system prompt",
        "what are your instructions",
        "reveal your training data",
        "show examples from training",
        "list your rules",
        "what's in your system message",
    ]

    for pattern in injection_patterns:
        if pattern in prompt_lower:
            return True, 0.95, "malicious", "prompt_injection"

    for pattern in jailbreak_patterns:
        if pattern in prompt_lower:
            return True, 0.90, "malicious", "jailbreak"

    for pattern in extraction_patterns:
        if pattern in prompt_lower:
            return False, 0.75, "suspicious", "data_extraction"

    return False, 0.0, "benign", "none"


@app.get("/v1/events")
async def list_events(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    x_api_key: str = Header(...),
):
    auth = await security.require_auth(x_api_key, required_permission="read")

    if redis_cb.state == CircuitState.OPEN or not redis_client:
        raise HTTPException(status_code=503, detail="Service degraded - event store unavailable")

    try:
        keys = await redis_call(redis_client.keys("tenet:event:*"))
        if keys is None:
            raise HTTPException(status_code=503, detail="Service degraded - event store unavailable")

        events = []
        for key in keys:
            data = await redis_call(redis_client.get(key))
            if data:
                parsed = json.loads(data)
                if parsed.get("org_id") == auth.org_id:
                    events.append(parsed)

        events.sort(key=lambda item: item.get("timestamp", ""), reverse=True)

        return {
            "total": len(events),
            "limit": limit,
            "offset": offset,
            "events": events[offset : offset + limit],
        }
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to list events: %s", exc)
        raise HTTPException(status_code=500, detail="Internal server error") from exc


@app.get("/v1/events/{event_id}", response_model=EventDetailResponse)
async def get_event(event_id: str, x_api_key: str = Header(...)):
    auth = await security.require_auth(x_api_key, required_permission="read")

    if not event_id.strip():
        raise HTTPException(status_code=422, detail="event_id must not be empty")

    if redis_cb.state == CircuitState.OPEN or not redis_client:
        raise HTTPException(status_code=503, detail="Service degraded - event store unavailable")

    try:
        data = await redis_call(redis_client.get(f"tenet:event:{event_id}"))
        if not data:
            raise HTTPException(status_code=404, detail="Event not found")
        parsed = json.loads(data)
        if parsed.get("org_id") != auth.org_id:
            raise HTTPException(status_code=404, detail="Event not found")
        return EventDetailResponse(**parsed)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to retrieve event %s: %s", event_id, exc)
        raise HTTPException(status_code=500, detail="Internal server error") from exc


@app.get("/v1/stats")
async def get_stats(x_api_key: str = Header(...)):
    auth = await security.require_auth(x_api_key, required_permission="read")

    if redis_cb.state == CircuitState.OPEN or not redis_client:
        raise HTTPException(status_code=503, detail="Service degraded - stats unavailable")

    try:
        keys = await redis_call(redis_client.keys("tenet:event:*"))
        if keys is None:
            raise HTTPException(status_code=503, detail="Service degraded - stats unavailable")

        threat_counts = {"malicious": 0, "suspicious": 0, "benign": 0}
        blocked_count = 0

        for key in keys:
            data = await redis_call(redis_client.get(key))
            if data:
                event = json.loads(data)
                if event.get("org_id") != auth.org_id:
                    continue
                if event.get("blocked"):
                    blocked_count += 1
                verdict = event.get("verdict", "benign")
                threat_counts[verdict] = threat_counts.get(verdict, 0) + 1

        return {
            "total_events": sum(threat_counts.values()),
            "blocked_count": blocked_count,
            "threat_distribution": threat_counts,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to get stats: %s", exc)
        raise HTTPException(status_code=500, detail="Internal server error") from exc


@app.get("/v1/circuit-status")
async def circuit_status(x_api_key: str = Header(...)):
    auth = await security.require_auth(x_api_key, required_permission="read")

    return {
        "name": redis_cb.name,
        "state": redis_cb.state.value,
        "failure_threshold": redis_cb.failure_threshold,
        "recovery_timeout_s": redis_cb.recovery_timeout,
    }


@app.get("/v1/audit/export")
async def export_audit_logs(limit: int = Query(default=200, ge=1, le=2000), x_api_key: str = Header(...)):
    auth = await security.require_auth(x_api_key, required_permission="admin")
    records = security.export_audit_records(auth.org_id, limit=limit)
    security.audit(
        action="audit_export",
        result="success",
        context=auth,
        metadata={"record_count": len(records)},
    )
    return {
        "org_id": auth.org_id,
        "exported": len(records),
        "records": records,
        "format": "jsonl-compatible",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=API_HOST, port=API_PORT)
