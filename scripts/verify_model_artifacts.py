#!/usr/bin/env python3
"""Validate trained model artifacts for production readiness."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


REQUIRED_FILES = ["prompt_detector.joblib", "vectorizer.joblib", "metadata.json", "checksums.json"]
REQUIRED_METADATA_FIELDS = [
    "schema_version",
    "trained_at",
    "accuracy",
    "model_type",
    "model_family",
    "task",
    "label_mapping",
    "feature_extractor",
    "artifact_files",
    "version",
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve_artifact_path(base_dir: Path, filename: str) -> Path | None:
    """Resolve artifact path and ensure it stays inside the model directory."""
    candidate = (base_dir / filename).resolve()
    try:
        candidate.relative_to(base_dir.resolve())
    except ValueError:
        return None
    return candidate


def validate(model_path: Path) -> list[str]:
    errors: list[str] = []

    for name in REQUIRED_FILES:
        if not (model_path / name).exists():
            errors.append(f"Missing required file: {name}")

    metadata_file = model_path / "metadata.json"
    if metadata_file.exists():
        try:
            metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
            missing = [f for f in REQUIRED_METADATA_FIELDS if f not in metadata]
            if missing:
                errors.append(f"metadata.json missing fields: {', '.join(missing)}")
        except json.JSONDecodeError as exc:
            errors.append(f"metadata.json is invalid JSON: {exc}")

    checksums_file = model_path / "checksums.json"
    if checksums_file.exists():
        try:
            checksums = json.loads(checksums_file.read_text(encoding="utf-8"))
            artifacts = checksums.get("artifacts", {})
            if not artifacts:
                errors.append("checksums.json has no artifacts entries")
            for filename, expected_digest in artifacts.items():
                artifact_path = _resolve_artifact_path(model_path, filename)
                if artifact_path is None:
                    errors.append(f"checksums.json contains invalid artifact path: {filename}")
                    continue
                if not artifact_path.exists():
                    errors.append(f"checksums.json references missing file: {filename}")
                    continue
                actual_digest = _sha256(artifact_path)
                if actual_digest != expected_digest:
                    errors.append(
                        f"Checksum mismatch for {filename}: expected {expected_digest}, got {actual_digest}"
                    )
        except json.JSONDecodeError as exc:
            errors.append(f"checksums.json is invalid JSON: {exc}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate model artifacts in a target directory")
    parser.add_argument("--model-path", default="models/trained", help="Path to model artifact directory")
    args = parser.parse_args()

    model_path = Path(args.model_path)
    if not model_path.exists():
        print(f"ERROR: Model path does not exist: {model_path}")
        return 2

    errors = validate(model_path)
    if errors:
        print("ERROR: Model artifact validation failed:")
        for err in errors:
            print(f" - {err}")
        return 1

    print(f"OK: Model artifacts are valid at {model_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
