#!/usr/bin/env python3
"""SBOM Generator for TENET-AI - CycloneDX & SPDX formats"""

import json
import os
from datetime import datetime

print("=" * 60)
print("🚀 TENET-AI SBOM Generator")
print("=" * 60)

# Step 1: Collect Python dependencies from requirements.txt
print("\n📦 Collecting Python dependencies...")
python_deps = []

if os.path.exists("requirements.txt"):
    with open("requirements.txt", "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if ">=" in line:
                    parts = line.split(">=")
                    name = parts[0].strip()
                    version = parts[1].strip()
                elif "==" in line:
                    parts = line.split("==")
                    name = parts[0].strip()
                    version = parts[1].strip()
                else:
                    name = line
                    version = "latest"
                
                python_deps.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "pypi"
                })

print(f"  ✅ Found {len(python_deps)} Python packages")

# Step 2: Collect Node.js dependencies from dashboard/package.json
print("\n📦 Collecting Node.js dependencies...")
node_deps = []

if os.path.exists("dashboard/package.json"):
    with open("dashboard/package.json", "r") as f:
        package_data = json.load(f)
    
    # Get regular dependencies
    for name, version in package_data.get("dependencies", {}).items():
        version = version.replace("^", "").replace("~", "")
        node_deps.append({
            "name": name,
            "version": version,
            "ecosystem": "npm"
        })
    
    # Get dev dependencies
    for name, version in package_data.get("devDependencies", {}).items():
        version = version.replace("^", "").replace("~", "")
        node_deps.append({
            "name": name,
            "version": version,
            "ecosystem": "npm",
            "scope": "dev"
        })

print(f"  ✅ Found {len(node_deps)} Node.js packages")

# Step 3: Combine all dependencies
all_deps = python_deps + node_deps
print(f"\n📊 TOTAL DEPENDENCIES: {len(all_deps)}")

# Step 4: Generate CycloneDX SBOM
print("\n📝 Generating CycloneDX SBOM...")

cyclonedx_sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": datetime.now().isoformat(),
        "component": {
            "type": "application",
            "name": "TENET-AI",
            "version": "1.0.0"
        }
    },
    "components": []
}

for dep in all_deps:
    cyclonedx_sbom["components"].append({
        "name": dep["name"],
        "version": dep["version"],
        "type": "library",
        "purl": f"pkg:{dep['ecosystem']}/{dep['name']}@{dep['version']}"
    })

with open("sbom_cyclonedx.json", "w") as f:
    json.dump(cyclonedx_sbom, f, indent=2)

print("  ✅ sbom_cyclonedx.json")

# Step 5: Generate SPDX SBOM
print("\n📝 Generating SPDX SBOM...")

spdx_sbom = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "TENET-AI SBOM",
    "documentNamespace": f"https://github.com/TENET-DEV-AI/TENET-AI/sbom/{datetime.now().isoformat()}",
    "creationInfo": {
        "created": datetime.now().isoformat(),
        "creators": ["Tool: TENET-AI-SBOM-Generator"]
    },
    "packages": []
}

for idx, dep in enumerate(all_deps):
    spdx_sbom["packages"].append({
        "name": dep["name"],
        "SPDXID": f"SPDXRef-{idx}",
        "versionInfo": dep["version"],
        "downloadLocation": "NOASSERTION",
        "licenseConcluded": "NOASSERTION"
    })

with open("sbom_spdx.json", "w") as f:
    json.dump(spdx_sbom, f, indent=2)

print("  ✅ sbom_spdx.json")

print("\n" + "=" * 60)
print("✅ SBOM GENERATION COMPLETE!")
print("📄 Files created:")
print("   - sbom_cyclonedx.json")
print("   - sbom_spdx.json")
print("=" * 60)