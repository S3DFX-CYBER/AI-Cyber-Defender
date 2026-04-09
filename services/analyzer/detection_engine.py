"""Core detection engine for multi-turn and agentic attack detection."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class EngineResult:
    """Normalized result from detection engine."""

    risk_score: float
    verdict: str
    threat_type: Optional[str]
    confidence: float
    details: Dict[str, Any]


class DetectionEngine:
    """Detection engine with policy-driven rules and optional transformer model."""

    DEFAULT_POLICY_PATH = Path(__file__).parent / "policy" / "default_policy.yaml"

    def __init__(self, redis_client=None):
        self.redis_client = redis_client
        self.policy = self._load_policy()
        self._session_cache: Dict[str, Dict[str, Any]] = {}
        self._backend = os.getenv("MODEL_BACKEND", "bert").lower()
        self._transformer_model = None
        self._load_model_backend()

    def _load_policy(self) -> Dict[str, Any]:
        policy_path = Path(os.getenv("POLICY_PATH", str(self.DEFAULT_POLICY_PATH)))
        try:
            with policy_path.open("r", encoding="utf-8") as handle:
                policy = yaml.safe_load(handle) or {}
            return policy
        except Exception:
            logger.exception("Failed to load policy file at %s", policy_path)
            return {}

    def _load_model_backend(self) -> None:
        if self._backend not in {"bert", "deberta"}:
            logger.info("Using sklearn backend")
            return

        model_id = os.getenv("TRANSFORMER_MODEL_ID", "distilbert-base-uncased-finetuned-sst-2-english")
        try:
            from transformers import pipeline

            self._transformer_model = pipeline("text-classification", model=model_id)
            logger.info("Loaded transformer backend model=%s", model_id)
        except Exception:
            logger.warning(
                "Transformer backend unavailable. Falling back to sklearn globals if present."
            )
            self._transformer_model = None

    def _merged_policy(self, organization_id: Optional[str]) -> Dict[str, Any]:
        merged = dict(self.policy)
        org_overrides = (self.policy.get("organizations") or {}).get(organization_id or "", {})
        for key, value in org_overrides.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = {**merged[key], **value}
            else:
                merged[key] = value
        return merged

    def _score_patterns(self, text: str, patterns: Dict[str, float]) -> Dict[str, Any]:
        text_low = text.lower()
        matched: List[str] = []
        max_score = 0.0
        for pattern, score in patterns.items():
            if pattern in text_low:
                matched.append(pattern)
                max_score = max(max_score, float(score))
        return {"matched": matched, "score": max_score}

    def _score_agent_chain(self, agent_trace: Optional[List[Dict[str, Any]]], policy: Dict[str, Any]) -> Dict[str, Any]:
        if not agent_trace:
            return {"score": 0.0, "flags": []}

        monitor = policy.get("agentic_chain_monitor", {})
        flags: List[str] = []
        score = 0.0
        patterns = monitor.get("tool_injection_patterns", {})

        for hop in agent_trace:
            tool_call = str(hop.get("tool_call", "")).lower()
            agent_name = str(hop.get("agent", "")).lower()
            payload = str(hop.get("payload", "")).lower()
            for pattern, s in patterns.items():
                if pattern in tool_call or pattern in payload or pattern in agent_name:
                    flags.append(pattern)
                    score = max(score, float(s))

        max_hops = int(monitor.get("max_hops", 0) or 0)
        if max_hops and len(agent_trace) > max_hops:
            flags.append("excessive_agent_hops")
            score = max(score, float(monitor.get("excessive_hops_score", 0.7)))

        return {"score": score, "flags": sorted(set(flags))}

    def _score_response_leak(self, response_text: Optional[str], policy: Dict[str, Any]) -> Dict[str, Any]:
        if not response_text:
            return {"score": 0.0, "matched": []}
        leak_policy = policy.get("response_scanning", {})
        patterns = leak_policy.get("data_leak_patterns", {})
        return self._score_patterns(response_text, patterns)

    def _session_key(self, organization_id: Optional[str], session_id: Optional[str]) -> str:
        return f"{organization_id or 'default'}:{session_id or 'anon'}"

    def _get_session_state(self, key: str) -> Dict[str, Any]:
        state = self._session_cache.get(key, {"history": [], "risk_accumulator": 0.0})
        return state

    def _save_session_state(self, key: str, state: Dict[str, Any]) -> None:
        self._session_cache[key] = state

    def _model_score(self, prompt: str, sklearn_fallback=None) -> Dict[str, float]:
        if self._transformer_model:
            out = self._transformer_model(prompt[:2048])[0]
            label = str(out.get("label", "")).lower()
            score = float(out.get("score", 0.0))
            # Map POSITIVE/NEGATIVE style labels into maliciousness score.
            malicious = score if "malicious" in label or "negative" in label else (1.0 - score)
            return {"risk_score": max(0.0, min(1.0, malicious)), "confidence": score}

        if sklearn_fallback is not None:
            return sklearn_fallback(prompt)

        return {"risk_score": 0.0, "confidence": 0.0}

    def analyze(
        self,
        prompt: str,
        organization_id: Optional[str] = None,
        session_id: Optional[str] = None,
        response_text: Optional[str] = None,
        agent_trace: Optional[List[Dict[str, Any]]] = None,
        sklearn_fallback=None,
    ) -> EngineResult:
        policy = self._merged_policy(organization_id)
        rules = policy.get("rules", {})

        prompt_eval = self._score_patterns(prompt, rules.get("prompt_patterns", {}))
        response_eval = self._score_response_leak(response_text, policy)
        chain_eval = self._score_agent_chain(agent_trace, policy)
        model_eval = self._model_score(prompt, sklearn_fallback=sklearn_fallback)

        key = self._session_key(organization_id, session_id)
        state = self._get_session_state(key)
        state["history"].append(
            {
                "prompt": prompt[:200],
                "prompt_score": prompt_eval["score"],
                "model_score": model_eval["risk_score"],
            }
        )
        state["history"] = state["history"][-20:]
        state["risk_accumulator"] = min(1.0, state.get("risk_accumulator", 0.0) + prompt_eval["score"] * 0.2)
        self._save_session_state(key, state)

        session_score = float(state.get("risk_accumulator", 0.0))

        risk_score = max(
            prompt_eval["score"],
            model_eval["risk_score"],
            response_eval["score"],
            chain_eval["score"],
            session_score,
        )

        thresholds = policy.get("thresholds", {})
        malicious_t = float(thresholds.get("malicious", 0.8))
        suspicious_t = float(thresholds.get("suspicious", 0.5))

        if risk_score >= malicious_t:
            verdict = "malicious"
        elif risk_score >= suspicious_t:
            verdict = "suspicious"
        else:
            verdict = "benign"

        threat_signals = {
            "prompt": prompt_eval["score"],
            "agent_chain": chain_eval["score"],
            "response": response_eval["score"],
            "model": model_eval["risk_score"],
            "session": session_score,
        }
        threat_type = max(threat_signals, key=threat_signals.get)
        if threat_signals[threat_type] <= 0.0:
            threat_type = None

        return EngineResult(
            risk_score=float(risk_score),
            verdict=verdict,
            threat_type=threat_type,
            confidence=max(model_eval["confidence"], 0.55 if risk_score > 0 else 1.0),
            details={
                "matched_patterns": prompt_eval["matched"],
                "response_matches": response_eval["matched"],
                "agent_chain_flags": chain_eval["flags"],
                "policy_version": policy.get("version", "unknown"),
                "session_events": len(state.get("history", [])),
                "threat_signals": threat_signals,
            },
        )

    def append_feedback(
        self,
        *,
        prompt: str,
        predicted_verdict: str,
        analyst_verdict: str,
        notes: Optional[str] = None,
    ) -> str:
        feedback_dir = Path(os.getenv("FEEDBACK_PATH", "./data/feedback"))
        feedback_dir.mkdir(parents=True, exist_ok=True)
        target = feedback_dir / "analyst_feedback.jsonl"
        record = {
            "prompt": prompt,
            "predicted_verdict": predicted_verdict,
            "analyst_verdict": analyst_verdict,
            "notes": notes,
        }
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        return str(target)
