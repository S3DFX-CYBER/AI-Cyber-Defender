"""Tenant-aware authentication, RBAC, quotas, and audit logging utilities."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from fastapi import HTTPException


DEFAULT_ROLE_PERMISSIONS: dict[str, set[str]] = {
    "viewer": {"read"},
    "ingest": {"read", "ingest", "analyze"},
    "analyst": {"read", "analyze"},
    "admin": {"read", "ingest", "analyze", "admin"},
}


@dataclass(frozen=True)
class AuthContext:
    org_id: str
    key_id: str
    role: str
    permissions: set[str]
    rpm_limit: int
    daily_quota: int


class SecurityManager:
    """Encapsulates multi-tenant auth, RBAC, quotas, and audit chain logging."""

    def __init__(
        self,
        service_name: str,
        redis_call: Optional[Callable[[Any], Any]] = None,
        redis_client_getter: Optional[Callable[[], Any]] = None,
    ) -> None:
        self.service_name = service_name
        self.redis_call = redis_call
        self.redis_client_getter = redis_client_getter
        self._memory_rate: dict[str, tuple[int, int]] = {}
        self._memory_quota: dict[str, tuple[int, int]] = {}
        self._last_hash = "0" * 64
        self._audit_lock = threading.Lock()

        self.audit_secret = os.getenv("AUDIT_HMAC_SECRET", "tenet-audit-dev-secret")
        self.audit_log_path = Path(os.getenv("AUDIT_LOG_PATH", "./logs/audit.log"))
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

        self.blocked_orgs = {
            org.strip() for org in os.getenv("BLOCKED_ORGS", "").split(",") if org.strip()
        }
        self.blocked_key_ids = {
            key.strip() for key in os.getenv("BLOCKED_KEY_IDS", "").split(",") if key.strip()
        }
        self.keys_config = self._load_keys_config()

    def _load_keys_config(self) -> dict[str, dict[str, Any]]:
        config_raw = os.getenv("TENET_API_KEYS_JSON", "")
        if config_raw:
            try:
                parsed = json.loads(config_raw)
                if not isinstance(parsed, dict):
                    raise ValueError("TENET_API_KEYS_JSON must be a JSON object")
                return parsed
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError(f"Invalid TENET_API_KEYS_JSON: {exc}") from exc

        fallback_key = os.getenv("API_KEY", "tenet-dev-key-change-in-production")
        return {
            fallback_key: {
                "org_id": os.getenv("DEFAULT_ORG_ID", "default-org"),
                "key_id": "default-key",
                "role": os.getenv("DEFAULT_API_ROLE", "admin"),
                "rpm_limit": int(os.getenv("DEFAULT_RPM_LIMIT", "120")),
                "daily_quota": int(os.getenv("DEFAULT_DAILY_QUOTA", "5000")),
            }
        }

    async def require_auth(self, x_api_key: str, required_permission: str) -> AuthContext:
        key_cfg = self.keys_config.get(x_api_key)
        if not key_cfg:
            raise HTTPException(status_code=401, detail="Invalid API key")

        role = key_cfg.get("role", "viewer")
        permissions = set(key_cfg.get("permissions", [])) or DEFAULT_ROLE_PERMISSIONS.get(role, {"read"})
        org_id = str(key_cfg.get("org_id", "default-org"))
        key_id = str(key_cfg.get("key_id", "unknown-key"))

        if org_id in self.blocked_orgs or key_id in self.blocked_key_ids:
            raise HTTPException(status_code=403, detail="API key temporarily blocked")

        if required_permission not in permissions:
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        context = AuthContext(
            org_id=org_id,
            key_id=key_id,
            role=role,
            permissions=permissions,
            rpm_limit=int(key_cfg.get("rpm_limit", 120)),
            daily_quota=int(key_cfg.get("daily_quota", 5000)),
        )

        await self._enforce_rate_limit(context)
        await self._enforce_daily_quota(context)
        return context

    async def _enforce_rate_limit(self, context: AuthContext) -> None:
        minute_bucket = int(time.time() // 60)
        key = f"rate:{context.org_id}:{context.key_id}:{minute_bucket}"
        count = await self._increment_counter(key, ttl=120, in_memory_bucket=self._memory_rate)
        if count > context.rpm_limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded for API key")

    async def _enforce_daily_quota(self, context: AuthContext) -> None:
        day_bucket = int(time.time() // 86400)
        key = f"quota:{context.org_id}:{context.key_id}:{day_bucket}"
        count = await self._increment_counter(key, ttl=172800, in_memory_bucket=self._memory_quota)
        if count > context.daily_quota:
            raise HTTPException(status_code=429, detail="Daily quota exceeded for API key")

    async def _increment_counter(
        self,
        key: str,
        ttl: int,
        in_memory_bucket: dict[str, tuple[int, int]],
    ) -> int:
        if self.redis_call and self.redis_client_getter and self.redis_client_getter():
            redis_client = self.redis_client_getter()
            count = await self.redis_call(redis_client.incr(key))
            if count is None:
                return self._increment_memory_counter(key, ttl, in_memory_bucket)
            try:
                int_count = int(count)
            except (TypeError, ValueError):
                return self._increment_memory_counter(key, ttl, in_memory_bucket)
            if int_count == 1:
                await self.redis_call(redis_client.expire(key, ttl))
            return int_count
        return self._increment_memory_counter(key, ttl, in_memory_bucket)

    def _increment_memory_counter(self, key: str, ttl: int, store: dict[str, tuple[int, int]]) -> int:
        now = int(time.time())
        count, expires_at = store.get(key, (0, now + ttl))
        if now >= expires_at:
            count = 0
            expires_at = now + ttl
        count += 1
        store[key] = (count, expires_at)
        return count

    def audit(
        self,
        action: str,
        result: str,
        context: Optional[AuthContext] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": self.service_name,
            "action": action,
            "result": result,
            "org_id": context.org_id if context else None,
            "key_id": context.key_id if context else None,
            "role": context.role if context else None,
            "metadata": metadata or {},
        }

        with self._audit_lock:
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(f"{self._last_hash}{canonical}".encode("utf-8")).hexdigest()
            signature = hmac.new(self.audit_secret.encode("utf-8"), digest.encode("utf-8"), hashlib.sha256).hexdigest()
            enriched = {
                **record,
                "prev_hash": self._last_hash,
                "hash": digest,
                "signature": signature,
            }
            with self.audit_log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(enriched) + "\n")
            self._last_hash = digest
            return enriched

    def export_audit_records(self, org_id: str, limit: int = 500) -> list[dict[str, Any]]:
        if not self.audit_log_path.exists():
            return []

        records: list[dict[str, Any]] = []
        with self.audit_log_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if item.get("org_id") == org_id:
                    records.append(item)

        return records[-limit:]
