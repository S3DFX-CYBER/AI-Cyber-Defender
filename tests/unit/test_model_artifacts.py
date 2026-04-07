"""Tests for model artifact hardening and validation behavior."""

import json
import hashlib
import tempfile
from pathlib import Path
import sys

import joblib

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "services" / "analyzer"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from model.phishing_model import PhishingDetector
from verify_model_artifacts import validate


class DummyVectorizer:
    def transform(self, value):
        return value


class DummyModel:
    def predict(self, value):
        return [0]

    def predict_proba(self, value):
        return [[1.0, 0.0]]


def _write_file(path: Path, content: str):
    path.write_text(content, encoding="utf-8")


def test_detector_fails_closed_without_metadata_or_checksums():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        joblib.dump(DummyModel(), base / "prompt_detector.joblib")
        joblib.dump(DummyVectorizer(), base / "vectorizer.joblib")

        detector = PhishingDetector(model_path=str(base))
        assert detector.model_loaded is False


def test_detector_rejects_checksum_path_traversal():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        joblib.dump(DummyModel(), base / "prompt_detector.joblib")
        joblib.dump(DummyVectorizer(), base / "vectorizer.joblib")
        _write_file(
            base / "metadata.json",
            json.dumps(
                {
                    "schema_version": "1.0.0",
                    "trained_at": "2026-01-01T00:00:00Z",
                    "accuracy": 1.0,
                    "model_type": "Dummy",
                    "model_family": "test_family",
                    "task": "task",
                    "label_mapping": {"0": "benign", "1": "malicious"},
                    "feature_extractor": {"type": "dummy"},
                    "artifact_files": ["prompt_detector.joblib", "vectorizer.joblib"],
                    "version": "1.0.0",
                }
            ),
        )
        _write_file(
            base / "checksums.json",
            json.dumps({"artifacts": {"../../etc/passwd": "abc"}}),
        )

        detector = PhishingDetector(model_path=str(base))
        assert detector.model_loaded is False


def test_detector_rejects_incomplete_metadata_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        model_file = base / "prompt_detector.joblib"
        vectorizer_file = base / "vectorizer.joblib"
        joblib.dump(DummyModel(), model_file)
        joblib.dump(DummyVectorizer(), vectorizer_file)

        _write_file(
            base / "metadata.json",
            json.dumps(
                {
                    "trained_at": "2026-01-01T00:00:00Z",
                    "accuracy": 1.0,
                    "model_type": "Dummy",
                    "version": "1.0.0",
                }
            ),
        )
        _write_file(
            base / "checksums.json",
            json.dumps(
                {
                    "artifacts": {
                        "prompt_detector.joblib": hashlib.sha256(model_file.read_bytes()).hexdigest(),
                        "vectorizer.joblib": hashlib.sha256(vectorizer_file.read_bytes()).hexdigest(),
                        "metadata.json": hashlib.sha256((base / "metadata.json").read_bytes()).hexdigest(),
                    }
                }
            ),
        )

        detector = PhishingDetector(model_path=str(base))
        assert detector.model_loaded is False


def test_validator_requires_checksums_manifest():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        _write_file(base / "prompt_detector.joblib", "x")
        _write_file(base / "vectorizer.joblib", "y")
        _write_file(
            base / "metadata.json",
            json.dumps(
                {
                    "trained_at": "2026-01-01T00:00:00Z",
                    "accuracy": 1.0,
                    "model_type": "Dummy",
                    "version": "1.0.0",
                }
            ),
        )

        errors = validate(base)
        assert any("checksums.json" in err for err in errors)


def test_validator_rejects_checksum_path_traversal():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        _write_file(base / "prompt_detector.joblib", "x")
        _write_file(base / "vectorizer.joblib", "y")
        _write_file(
            base / "metadata.json",
            json.dumps(
                {
                    "schema_version": "1.0.0",
                    "trained_at": "2026-01-01T00:00:00Z",
                    "accuracy": 1.0,
                    "model_type": "Dummy",
                    "model_family": "test_family",
                    "task": "task",
                    "label_mapping": {"0": "benign", "1": "malicious"},
                    "feature_extractor": {"type": "dummy"},
                    "artifact_files": ["prompt_detector.joblib", "vectorizer.joblib"],
                    "version": "1.0.0",
                }
            ),
        )
        _write_file(
            base / "checksums.json",
            json.dumps({"artifacts": {"../../etc/passwd": "abc"}}),
        )

        errors = validate(base)
        assert any("invalid artifact path" in err for err in errors)
