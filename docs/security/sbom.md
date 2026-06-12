# Software Bill of Materials (SBOM)

## Overview
TENET-AI publishes SBOMs for every release to ensure supply chain transparency and security compliance.

## 📦 SBOM Formats

| Format | File | Standard | Use Case |
|--------|------|----------|----------|
| CycloneDX | `sbom_cyclonedx.json` | OWASP Standard | Vulnerability scanning, Dependency-Track |
| SPDX | `sbom_spdx.json` | Linux Foundation | Compliance, Legal review |

## 📊 Current Dependencies
- **Python packages:** 18 (FastAPI, scikit-learn, pandas, etc.)
- **Node.js packages:** 17 (React, Vite, Recharts, etc.)

## 🔍 Viewing SBOM Contents

```bash
# View all dependencies
cat sbom_cyclonedx.json | jq '.components[] | {name, version}'

# Count total dependencies
cat sbom_cyclonedx.json | jq '.components | length'

# Search for specific package
cat sbom_cyclonedx.json | jq '.components[] | select(.name=="fastapi")'