# RAGIN: RAG-Powered Intelligent Honeypots
## Model-Agnostic Adaptive Honeypot Intelligence Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

**RAGIN** is a fully autonomous honeypot intelligence system combining:
- **C1 (Chrollo)**: 150-feature Random Forest behavioral classifier
- **C2 (Don)**: Hybrid dense+sparse RAG with poisoning defense
- **C3 (Hisoka)**: Skill-stratified adaptive LLM deception

## 🎯 Key Features

- **Model Agnostic**: Switch between Ollama, HuggingFace, OpenAI-compatible APIs with ONE config line
- **Production-Ready**: Redis async pipeline, FastAPI REST API, Docker deployment
- **Research-Grade**: Full ablation study, metrics, citations, reproducible results
- **780K+ Document RAG**: Exploit-DB, MITRE ATT&CK, OSINT IP reputation
- **Real-Time Skill Profiling**: Novice/Intermediate/Expert classification
- **Adaptive Deception**: Tier-specific honeypot responses via LLM

## 🚀 Quick Start

### Prerequisites
```bash
# Option 1: Ollama (Recommended for local deployment)
curl https://ollama.ai/install.sh | sh
ollama pull qwen2:7b
ollama pull nomic-embed-text

# Option 2: LM Studio / vLLM (OpenAI-compatible)
# Start your server at http://localhost:8000

# Infrastructure
docker-compose up -d redis qdrant
```

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
┌─────────────────────────────────────────────────────────────┐
│  Cowrie Honeypot Cluster (20 containers)                   │
│  SSH/Telnet/HTTP/MySQL sessions → Redis                    │
└────────────────┬────────────────────────────────────────────┘
                 │
         ┌───────▼────────┐
         │  Redis Broker  │
         │  Async Queues  │
         └───────┬────────┘
                 │
    ┌────────────▼─────────────┐
    │  C1: Chrollo Classifier  │
    │  150-feature RF          │
    │  Escalation threshold τ  │
    └────────────┬─────────────┘
                 │ (malicious & conf >= τ)
    ┌────────────▼─────────────┐
    │  C2: Don RAG Engine      │
    │  Hybrid retrieval        │
    │  Qdrant + BM25           │
    │  IQS scoring             │
    └────────────┬─────────────┘
                 │
    ┌────────────▼─────────────┐
    │  C3: Hisoka Deceptor     │
    │  Skill classifier        │
    │  Adaptive LLM response   │
    └──────────────────────────┘
```

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
Configuration              Accuracy   FPR    F1
────────────────────────────────────────────────
Chrollo-only               94.2%     3.8%   0.93
Chrollo + Don              96.1%     2.4%   0.95
Full RAGIN (C1+C2+C3)      97.8%     1.2%   0.97
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
> Youssef Hamdi et al., 2024

Key Contributions:
1. **Model-agnostic framework** supporting Ollama, HuggingFace, OpenAI-compatible APIs
2. **Hybrid RAG** (dense+sparse) with 3-stage credibility scoring
3. **Real-time skill profiling** (Novice/Intermediate/Expert)
4. **Adaptive LLM deception** with tier-specific prompt templates
5. **Production-ready** async pipeline with <2s latency

## 📊 Performance

- **Accuracy**: 97.8% (full RAGIN)
- **False Positive Rate**: 1.2%
- **F1 Score**: 0.97
- **Latency**: <2000ms end-to-end
- **Scalability**: 20 concurrent honeypots
- **RAG Corpus**: 780K+ documents

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
