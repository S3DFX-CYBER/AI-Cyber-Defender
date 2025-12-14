# 🛡️ TENET AI

**AI-Assisted Cyber Threat Detection & Response Prototype**

<div align="center">

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

**TENET AI** is a research-driven cybersecurity prototype that explores how artificial intelligence and machine learning can assist in detecting and responding to modern, AI-enabled cyber threats such as phishing, prompt injection, malicious automation, and abnormal API behavior.

This project focuses on **system design, detection logic, and security workflows**, rather than claiming production-grade coverage.

---

## 🎯 Project Objective

The goal of TENET AI is to **study and demonstrate** how an AI-assisted defense system can:

- **Ingest security telemetry** from multiple sources (email gateways, API logs, user actions)
- **Apply ML/LLM-based analysis** to identify suspicious patterns
- **Correlate signals** into meaningful risk scores
- **Support analysts** with actionable context and evidence
- **Automate low-risk defensive actions** (alert, quarantine, block)

This project is intentionally built as a **learning and engineering exercise**, aligned with real SOC and AppSec workflows.

---

## ✨ Core Capabilities

### Threat Signal Ingestion
Accepts structured security events from email gateways, web proxies, and API logs

### AI-Assisted Detection
Experimental models for:
- Phishing content analysis
- Prompt injection pattern detection
- Suspicious API behavior analysis
- Malicious URL identification

### Risk Scoring Engine
Combines multiple detection signals into a unified confidence score with explainable reasoning

### Analyst Review Loop
Lightweight interface for security analysts to review alerts, provide feedback, and refine detection logic

### Response Simulation
Demonstrates how automated defensive actions could be triggered (quarantine, alert escalation, URL blocking)

> ⚠️ **Important**: This project **does not claim full coverage or guaranteed detection**. It is a prototype designed to reflect real-world security concepts and workflows.

---

## 🧠 Why This Project Exists

Modern attackers increasingly leverage:
- AI-generated phishing campaigns
- Automated abuse at scale
- Logic exploitation and prompt manipulation
- Adversarial machine learning techniques

Most traditional security tools lag behind these emerging threats. TENET AI explores **how defenders can close that gap** using AI responsibly and ethically.

---

## 🏗️ System Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Event Sources  │────▶│  Ingestion API   │────▶│  Message Queue  │
│ (Email/API/Web) │     │    (FastAPI)     │     │     (Redis)     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                          │
                                                          ▼
                        ┌─────────────────────────────────────────┐
                        │        Analysis Engine                  │
                        │  ┌──────────────┐  ┌─────────────────┐ │
                        │  │ ML Models    │  │ Heuristics      │ │
                        │  │ (scikit)     │  │ (Pattern Match) │ │
                        │  └──────────────┘  └─────────────────┘ │
                        └─────────────────────────────────────────┘
                                          │
                                          ▼
                        ┌─────────────────────────────────────────┐
                        │        Risk Scoring Engine              │
                        │    (Signal Correlation + Weighting)     │
                        └─────────────────────────────────────────┘
                                          │
                        ┌─────────────────┴─────────────────┐
                        │                                   │
                        ▼                                   ▼
            ┌────────────────────┐             ┌─────────────────────┐
            │  Analyst Portal    │             │ Response Simulator  │
            │  (React Frontend)  │             │  (Automated Actions)│
            └────────────────────┘             └─────────────────────┘
```

**Component Overview:**
- **Ingestion Service**: Collects and validates incoming security events
- **Analysis Engine**: Applies ML models and heuristic detection rules
- **Risk Scoring**: Aggregates signals into actionable threat scores
- **Analyst Portal**: Web interface for alert review and feedback
- **Response Simulator**: Demonstrates automated defensive workflows

---

## 🛠️ Technology Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.11, FastAPI |
| **ML/AI** | scikit-learn, Transformers (experimental) |
| **Database** | PostgreSQL |
| **Storage** | MinIO (S3-compatible) |
| **Queue/Cache** | Redis |
| **Frontend** | React 18 + TypeScript |
| **Container** | Docker, Docker Compose |
| **CI/CD** | GitHub Actions |
| **Testing** | pytest, pytest-asyncio |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11 or higher
- Docker and Docker Compose
- 4GB RAM minimum

### Local Setup (Prototype Mode)

```bash
# Clone repository
git clone https://github.com/yourusername/tenet-ai
cd tenet-ai

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run prototype demo
python prototype/AI_Defender_Prototype.py
```

### Docker Setup (Full Stack)

```bash
# Copy environment template
cp .env.template .env

# Start all services
docker-compose up -d

# Check service health
docker-compose ps

# View logs
docker-compose logs -f

# Access analyst portal
open http://localhost:3000
```

---

## 📌 Current Scope (MVP Phase)

**What's Included:**
- Demonstration-level detection logic for phishing and prompt injection
- Basic risk scoring and correlation engine
- Analyst feedback loop for continuous improvement
- System architecture aligned with SOC workflows
- Containerized deployment for local testing

**Intentionally Not Included:**
- Production-grade hardening and security controls
- Full SIEM/SOAR integrations (simulated only)
- Real-world enforcement capabilities
- SLA guarantees or uptime commitments
- Multi-tenancy or enterprise SSO

This is a **research prototype** designed to demonstrate concepts, not a production security product.

---

## 🗺️ Future Exploration Areas

- Enhanced anomaly detection using unsupervised learning
- Improved prompt injection detection with transformer models
- Deeper API abuse pattern analysis
- Graph-based attack correlation
- Expanded analyst tooling and workflow automation
- Integration with threat intelligence feeds

---

## 📚 Project Structure

```
tenet-ai/
├── prototype/              # Initial prototype script
├── services/              # Microservices
│   ├── ingest/           # Event ingestion API
│   ├── analyzer/         # ML analysis engine
│   └── orchestrator/     # Response orchestration
├── ui/                   # React analyst portal
├── tests/                # Test suites
├── docs/                 # Documentation
├── infra/                # Docker and K8s configs
└── data/                 # Sample datasets
```

---

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=services --cov-report=html

# Run specific test suite
pytest tests/unit/test_phishing_detector.py

# Code quality checks
black --check .
ruff check .
bandit -r services/
```

---

## 👤 Author

**Savio D'Souza**  
Cybersecurity & Application Security Researcher  
Focus Areas: Application Security, Business Logic Vulnerabilities, AI Security

---

## 🔒 Security & Ethical Use

TENET AI is a **defensive security tool** intended for:
- Education and research
- Security architecture exploration
- Proof-of-concept demonstrations

**User Responsibilities:**
- Obtain proper authorization before deployment
- Comply with applicable laws and regulations
- Use responsibly and ethically
- Do not use for unauthorized testing or malicious purposes

For security concerns or vulnerability reports, see [SECURITY.md](SECURITY.md).

---

## 🤝 Contributing

Contributions are welcome! This is an open research project. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

---

## 📞 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/tenet-ai/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/tenet-ai/discussions)
- **Email**: security@yourcompany.com

---

### ⚠️ Honest Positioning

TENET AI is a **research prototype** that demonstrates security engineering concepts. It is:

✅ Architecturally sound and well-designed  
✅ Based on real SOC and AppSec workflows  
✅ Honest about its capabilities and limitations  
✅ Suitable for learning, research, and demonstration  

❌ Not a production-ready enterprise security product  
❌ Not a replacement for commercial security tools  
❌ Not claiming guaranteed threat detection  

This project showcases **system design thinking, security domain knowledge, and responsible AI application** — exactly what technical recruiters and hiring managers look for.

---

**Built with security, transparency, and education in mind.** 🛡️
