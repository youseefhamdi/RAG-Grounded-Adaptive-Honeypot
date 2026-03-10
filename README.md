# RAGIN: RAG-Grounded Adaptive Honeypot Intelligence

## Per-Attacker Behavioral Profiling for Threat Classification and Deception

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Paper](https://img.shields.io/badge/Paper-2026-green.svg)](https://github.com/youseefhamdi/SPECTRA-CyberDefense)

**RAGIN** (Retrieval-Augmented Honeypot Intelligence Network) is a three-component adaptive cyber deception framework combining:

- **C1 (Chrollo)**: 150-feature Random Forest behavioral classifier — 94.2% accuracy, 3.1% FPR
- **C2 (Don)**: Hybrid dense+sparse RAG engine over 780K+ threat intelligence documents with PageRank-based poisoning defense
- **C3 (Hisoka)**: Per-attacker skill-stratified adaptive LLM deception — 4.1× dwell time increase

> 📄 **Paper**: Ibrahim, Y. H. Z., & Salama, M. K. (2026). *RAGIN: RAG-Grounded Adaptive Honeypot Intelligence with Per-Attacker Behavioral Profiling for Threat Classification and Deception.*

---

## 🎯 Key Features

- **Model-Agnostic**: Switch between Ollama, HuggingFace, or OpenAI-compatible APIs with **one config line**
- **RAG-Grounded**: 780K+ documents (Exploit-DB, MITRE ATT&CK, OSINT) — 80× larger than prior corpora
- **Poisoning Defense**: PageRank-based document credibility scoring at index ingestion
- **Real-Time Skill Profiling**: Novice / Intermediate / Expert classification in 100 ms
- **Adaptive Deception**: Tier-specific Qwen-32B LLM responses maximize attacker dwell time
- **Evidence-Cited Attribution**: Every MITRE ATT&CK mapping includes source provenance
- **Empirically Validated**: Full ablation study over 500 labeled attack sessions

---

## 🚀 Quick Start

### Prerequisites

```bash
# Option 1: Ollama (Recommended for local deployment)
curl https://ollama.ai/install.sh | sh
ollama pull qwen2.5:32b          # Paper model: Qwen-32B
ollama pull mistral              # Embeddings: Mistral-7B (768-dim)

# Option 2: vLLM / LM Studio (OpenAI-compatible)
# Start your server at http://localhost:8000

# Required infrastructure
docker-compose up -d qdrant      # Vector DB (required)
# Note: Redis is optional — used only for query caching optimization


### Installation
```bash
git clone https://github.com/yourusername/RAGIN.git
cd RAGIN
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Training Chrollo
```bash
# Using provided sample data
python -m protocols.p3chrollo.train --data data/sample_training.jsonl

# Or use the convenience script
chmod +x scripts/train_chrollo.sh
./scripts/train_chrollo.sh
```

### Running RAGIN

**Terminal 1: Orchestrator**
```bash
python -m pipeline.orchestrator
```

**Terminal 2: API Server**
```bash
python -m pipeline.apiserver
```

**Terminal 3: Submit Test Session**
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d @data/test_session.json
```

## 📊 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Cowrie Honeypot Cluster (20 Docker containers)              │
│  SSH / Telnet / HTTP / MySQL  →  Raw session telemetry       │
└────────────────────┬─────────────────────────────────────────┘
                     │ commands, network flows, file accesses
                     ▼
    ┌────────────────────────────┐
    │  C1: Chrollo Classifier    │
    │  150-feature Random Forest │
    │  Escalation threshold τ=0.85│
    └────────────────┬───────────┘
                     │ confidence ≥ 0.85 → escalate
                     ▼
    ┌────────────────────────────┐
    │  C2: Don RAG Engine        │
    │  Hybrid dense+sparse       │
    │  Qdrant (HNSW) + BM25      │
    │  PageRank credibility gate │
    │  780K docs / 50 ms latency │
    └────────────────┬───────────┘
                     │ top-10 docs + CVEs + MITRE techniques
                     ▼
    ┌────────────────────────────┐
    │  C3: Hisoka Deceptor       │
    │  Skill: Novice/Inter/Expert│
    │  Qwen-32B adaptive response│
    │  IQS-scored output         │
    └────────────────────────────┘

```

##Component Latency Budget

```

| Component                    | Latency  | % of Total |
| ---------------------------- | -------- | ---------- |
| C1 Chrollo (ML inference)    | 150 ms   | 5.7%       |
| C2 Don (RAG retrieval + LLM) | 2,100 ms | 79.2%      |
| C3 Hisoka (skill + response) | 400 ms   | 15.1%      |
| Total end-to-end             | 2,650 ms | 100%       |
```
- ** Optimization path: ANN tuning + Redis LRU cache projected to reduce total to ~950 ms (−64.2%) — see paper Section 3.5.

## 🔧 Configuration

### Switching Models (One Line!)

Edit `config/config.yaml`:

```yaml
model_provider:
  type: ollama  # Change to: huggingface | openaicompat
```

**That's it!** The entire pipeline (embeddings, LLM inference, deception) switches automatically.

### Provider Examples

**Ollama (Local)**
```yaml
type: ollama
ollama:
  base_url: http://localhost:11434
  llm_model: qwen2:7b
  embed_model: nomic-embed-text
```

**HuggingFace (Local GPU)**
```yaml
type: huggingface
huggingface:
  llm_model: microsoft/phi-3-mini-4k-instruct
  embed_model: sentence-transformers/all-mpnet-base-v2
  device: cuda
```

**LM Studio / vLLM**
```yaml
type: openaicompat
openaicompat:
  base_url: http://localhost:8000/v1
  llm_model: local-model
```

## 📈 Evaluation

Run ablation study (reproduces paper Table 17):

```bash
python -m evaluation.runeval --data data/test_sessions.jsonl
```

**Expected Results:**
```
Configuration                  Accuracy   FPR     F1
──────────────────────────────────────────────────────
Static Cowrie (no ML)            63.6%    10.0%   0.71
Signature IDS (Suricata 7.0)     71.5%     8.2%   0.76
C1 only  — Chrollo ML            89.5%     4.8%   0.91
C1 + C2  — + Don RAG             93.2%     3.5%   0.94
C1 + C2 + C3 — Full RAGIN        94.2%     3.1%   0.96

```

## 🧪 Testing

```bash
# Unit tests
pytest tests/test_chrollo.py -v
pytest tests/test_don.py -v
pytest tests/test_hisoka.py -v

# All tests
pytest tests/ -v
```

## 🐳 Docker Deployment

```bash
# Full system
docker-compose up -d

# Check health
curl http://localhost:8000/health

# View logs
docker-compose logs -f ragin
```

## 📚 API Documentation

### Submit Session
```bash
POST /analyze
{
  "session_id": "sess_001",
  "srcip": "192.168.1.100",
  "commands": ["ls", "cat /etc/passwd"],
  "auth_attempts": [],
  "files": []
}
```

### Retrieve Report
```bash
GET /report/{session_id}
```

Returns:
```json
{
  "session_id": "sess_001",
  "verdict": "malicious",
  "confidence": 0.923,
  "skill_level": "Expert",
  "cves": ["CVE-2024-1234"],
  "mitre_techniques": ["T1059.004"],
  "analysis": "...",
  "adaptive_response": "...",
  "iqs": 0.847,
  "latency_ms": {"chrollo": 12, "don": 340, "hisoka": 1200, "total": 1552}
}
```

## 📁 Project Structure

```
RAGIN/
├── config/
│   └── config.yaml              # Master configuration
├── core/
│   └── modelprovider.py         # Model abstraction layer
├── protocols/
│   ├── p3chrollo/               # C1: Classifier
│   │   ├── feature_extractor.py
│   │   ├── chrollo_classifier.py
│   │   └── train.py
│   ├── p2don/                   # C2: RAG Engine
│   │   ├── ingestion_pipeline.py
│   │   └── don_rag_engine.py
│   └── p4hisoka/                # C3: Deception
│       ├── skill_classifier.py
│       ├── prompt_templates.py
│       └── hisoka_deceptor.py
├── pipeline/
│   ├── orchestrator.py          # C1→C2→C3 wiring
│   └── apiserver.py             # FastAPI REST
├── evaluation/
│   ├── metrics.py
│   └── ablation.py
├── tests/
├── data/
├── models/
├── docker-compose.yml
└── requirements.txt
```

## 🔬 Research

Based on the paper:
> **RAGIN: RAG-Powered Intelligent Honeypots with Adaptive Deception**  
> Youssef Hamdi et al., 2026

Key Contributions:
1. **Model-agnostic framework** supporting Ollama, HuggingFace, OpenAI-compatible APIs
2. **Hybrid RAG** (dense+sparse) with 3-stage credibility scoring
3. **Real-time skill profiling** (Novice/Intermediate/Expert)
4. **Adaptive LLM deception** with tier-specific prompt templates
5. **Production-ready** async pipeline with <2s latency

## 📊 Performance

- **Detection Accuracy**: 94.2% (Full RAGIN C1+C2+C3)
- **False Positive Rate**: 3.1%
- **F1 Score**: 0.96
- **MITRE ATT&CK Mapping**: 92.1%
- **IQS (Intelligence Quality Score)**: 0.92
- **Attacker Dwell Time**: 4.1× increase vs. non-adaptive baseline
- **Threat Actor Attribution**: 67.2% coverage
- **End-to-End Latency**: 2,650 ms (projected <950 ms with caching)
- **Honeypot Cluster**: 20 concurrent Cowrie containers
- **RAG Corpus**: 780K+ documents (Exploit-DB, MITRE ATT&CK, OSINT)

## 🛠️ Troubleshooting

**Issue**: `Model not trained`
```bash
python -m protocols.p3chrollo.train --data data/sample_training.jsonl
```

**Issue**: Qdrant connection failed
```bash
docker-compose up -d qdrant
```

**Issue**: Redis connection failed
```bash
docker-compose up -d redis
```

## 🤝 Contributing

Contributions welcome! Please open issues or PRs.

## 📄 License

MIT License - see LICENSE file

## 📧 Contact

- **Author**: Youssef Hamdi
- **Email**: youssef.hamdi@example.com
- **GitHub**: [@youssefhamdi](https://github.com/youssefhamdi)

## 🙏 Acknowledgments

- Cowrie Honeypot Project
- Qdrant Vector Database
- Ollama Project
- HuggingFace Transformers

---

**⭐ Star this repo if RAGIN helped your research!**
