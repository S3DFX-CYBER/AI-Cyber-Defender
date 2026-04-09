"""SIEM connector utilities for Splunk HEC, Sentinel, and Elastic."""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Dict, Any

import httpx

logger = logging.getLogger(__name__)


class SIEMDispatcher:
    """Dispatches malicious events to configured SIEM backends."""

    def __init__(self) -> None:
        self.splunk_url = os.getenv("SPLUNK_HEC_URL", "").strip()
        self.splunk_token = os.getenv("SPLUNK_HEC_TOKEN", "").strip()
        self.sentinel_url = os.getenv("SENTINEL_INGEST_URL", "").strip()
        self.sentinel_token = os.getenv("SENTINEL_TOKEN", "").strip()
        self.elastic_url = os.getenv("ELASTIC_INGEST_URL", "").strip()
        self.elastic_api_key = os.getenv("ELASTIC_API_KEY", "").strip()
        self.timeout = float(os.getenv("SIEM_TIMEOUT_SECONDS", "2.5"))

    async def publish(self, event: Dict[str, Any]) -> None:
        tasks = []
        if self.splunk_url and self.splunk_token:
            tasks.append(self._post_splunk(event))
        if self.sentinel_url:
            tasks.append(self._post_sentinel(event))
        if self.elastic_url:
            tasks.append(self._post_elastic(event))

        if not tasks:
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                logger.warning("SIEM publish failed: %s", result)

    async def _post_splunk(self, event: Dict[str, Any]) -> None:
        payload = {"event": event, "source": "tenet-analyzer"}
        headers = {"Authorization": f"Splunk {self.splunk_token}"}
        await self._post(self.splunk_url, headers=headers, payload=payload)

    async def _post_sentinel(self, event: Dict[str, Any]) -> None:
        headers = {"Content-Type": "application/json"}
        if self.sentinel_token:
            headers["Authorization"] = f"Bearer {self.sentinel_token}"
        await self._post(self.sentinel_url, headers=headers, payload=event)

    async def _post_elastic(self, event: Dict[str, Any]) -> None:
        headers = {"Content-Type": "application/json"}
        if self.elastic_api_key:
            headers["Authorization"] = f"ApiKey {self.elastic_api_key}"
        await self._post(self.elastic_url, headers=headers, payload=event)

    async def _post(self, url: str, headers: Dict[str, str], payload: Dict[str, Any]) -> None:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(url, headers=headers, content=json.dumps(payload))
            response.raise_for_status()
