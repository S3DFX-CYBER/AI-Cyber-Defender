import time
from typing import Callable, Awaitable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from prometheus_client import Counter, Histogram, REGISTRY

# Define standard request metrics
REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"]
)

REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"]
)

# Define detection specific metrics
DETECTION_COUNT = Counter(
    "tenet_detections_total",
    "Total threats detected by type and verdict",
    ["service", "threat_type", "verdict"]
)

def increment_detection(service: str, threat_type: str, verdict: str) -> None:
    """Helper to increment detection counters."""
    if not threat_type:
        threat_type = "none"
    DETECTION_COUNT.labels(service=service, threat_type=threat_type, verdict=verdict).inc()


class PrometheusMiddleware(BaseHTTPMiddleware):
    """Middleware to collect basic HTTP metrics."""
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        start_time = time.time()
        
        method = request.method
        try:
            response = await call_next(request)
            status_code = str(response.status_code)
            
            route = request.scope.get("route")
            endpoint = route.path if route else request.url.path
            
            REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status_code).inc()
            REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(time.time() - start_time)
            
            return response
        except Exception:
            # If an unhandled exception occurs, assume 500 status code
            status_code = "500"
            route = request.scope.get("route")
            endpoint = route.path if route else request.url.path
            
            REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status_code).inc()
            REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(time.time() - start_time)
            raise
