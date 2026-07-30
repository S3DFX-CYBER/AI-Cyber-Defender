# Configuration Guide

TENET-AI uses a centralized configuration framework powered by Pydantic. Environment variables are strictly validated at startup to ensure safe deployments and fail-fast behavior.

## Required Secrets
These secrets must be set in your environment (or `.env` file) for production deployments:
- `API_KEY`: The API key used for securing endpoints.
- `AUDIT_HMAC_SECRET`: HMAC secret for securing audit logs.

## Core Configuration
- `LOG_LEVEL` (default: `INFO`): Global application logging level (e.g., `DEBUG`, `WARNING`, `ERROR`).

## Redis Settings
- `REDIS_HOST` (default: `localhost`): Hostname for the Redis server.
- `REDIS_PORT` (default: `6379`): Port for the Redis server.
- `REDIS_TIMEOUT_S` (default: `2.0`): Connection timeout in seconds.

## API Services
- `API_HOST` (default: `0.0.0.0`): Bind host for API services.
- `API_PORT` (default: `8000`): Port for the ingest service.
- `CORS_ORIGINS` (default: `http://localhost:3000`): Comma-separated list of allowed CORS origins for ingest.
- `CORS_ALLOWED_ORIGINS` (default: `https://localhost:3000,https://localhost:5173`): Comma-separated list for analyzer.

## Resilience (Circuit Breaker)
- `CB_FAILURE_THRESHOLD` (default: `3`): Number of failures before opening circuit.
- `CB_RECOVERY_TIMEOUT_S` (default: `30.0`): Seconds to wait before attempting recovery.
- `CB_HALF_OPEN_MAX_CALLS` (default: `1`): Number of calls permitted in half-open state.

## ML Analyzer Settings
- `MODEL_PATH` (default: `./models/trained`): Path to loaded threat detection models.
- `PROMPT_INJECTION_THRESHOLD` (default: `0.75`): Confidence threshold for blocking prompts.
- `SHUTDOWN_TIMEOUT` (default: `10.0`): Timeout for graceful shutdown.

## Security & Rate Limiting
- `AUDIT_LOG_PATH` (default: `./logs/audit.log`): File path for security audit logs.
- `BLOCKED_ORGS` (default: `""`): Comma-separated list of blocked organization IDs.
- `BLOCKED_KEY_IDS` (default: `""`): Comma-separated list of blocked API key IDs.
- `TENET_API_KEYS_JSON` (default: `""`): JSON-encoded dictionary defining valid API keys and scopes.
- `DEFAULT_ORG_ID` (default: `default-org`): Default organization ID for requests missing one.
- `DEFAULT_API_ROLE` (default: `admin`): Default role assigned.
- `DEFAULT_RPM_LIMIT` (default: `120`): Default Requests Per Minute limit.
- `DEFAULT_DAILY_QUOTA` (default: `5000`): Default daily request quota.

## Using `.env` Files
You can define these variables in a `.env` file at the root of the project. We provide a starter template:
```bash
cp .env.template .env.example
cp .env.example .env
```
