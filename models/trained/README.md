# Trained Model Artifacts (Production Contract)

This directory contains the production inference artifacts used by the analyzer service.

## Artifacts

- `prompt_detector.joblib`: binary classifier (`0=benign`, `1=malicious`).
- `vectorizer.joblib`: TF-IDF vectorizer used to transform raw prompts.
- `metadata.json`: model card + artifact contract.
- `checksums.json`: SHA-256 integrity manifest for artifact verification.

## Production requirements

1. Update `metadata.json` for every model retrain.
2. Regenerate `checksums.json` whenever any artifact changes.
3. Validate artifacts before deployment:

```bash
python scripts/verify_model_artifacts.py --model-path models/trained
```

4. Analyzer runtime requires `checksums.json` and blocks model loading if checksum verification fails.

## Deployment notes

- Keep this directory immutable in production images.
- Prefer replacing the entire directory atomically during model rollout.
- If checksum validation fails, deployment should be considered unhealthy.
