<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/PyTorch-2.1+-ee4c2c?logo=pytorch&logoColor=white" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
</p>

# SentinelLLM — Multi-Layer AI Security Framework

> **A 5-layer AI firewall** that protects LLM applications from prompt injection, jailbreaks, zero-day payloads, and data exfiltration — with real-time detection, MITRE ATT&CK mapping, and a live operator dashboard.

Built as a **VTU Final Year Project** | Dept. of CSE | DSATM

---

## Highlights

- **5 cascading security layers** — regex + entropy, DeBERTa-v3 + VAE anomaly, XGBoost + GNN session graph, dual-LLM policy verifier, Presidio PII scanner  
- **Real ML models** — not just heuristics; trained on 3,600+ injection/jailbreak samples from HuggingFace  
- **Graceful degradation** — every layer falls back to simulation if model weights or API keys are missing  
- **Live dashboard** — 7-tab operator console with real-time metrics, threat log, batch analysis, and attack simulator  
- **MITRE ATT&CK mapping** — each threat is tagged to an ATT&CK technique ID  

---

## Quick Start

### Prerequisites

- Python 3.10+  
- pip  
- (Optional) CUDA-capable GPU for faster training  

### 1. Clone & install

```bash
git clone https://github.com/<your-username>/SentinelLLM.git
cd SentinelLLM

pip install -r requirements.txt

# Required by Presidio (Layer 5)
python -m spacy download en_core_web_lg
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and paste your Groq API key from https://console.groq.com
```

> **No API key?** The server still works — Layer 4 uses a rule-based fallback instead of the LLM judge.

### 3. Train models (optional but recommended)

```bash
python scripts/train.py
```

Downloads datasets from HuggingFace, trains the VAE and XGBoost, and saves weights to `models/`. Takes ~15 min on an RTX 3050.

> **Skip training?** The server starts in full simulation mode. The dashboard will show each model as **SIM** instead of **LIVE**.

### 4. Start the server

```bash
python run.py
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

---

## Architecture

```
                 User Input
                     │
          ┌──────────▼──────────┐
          │   LAYER 1: SANITISE │  Regex patterns · Entropy scoring · Perplexity filter
          └──────────┬──────────┘
                     │
          ┌──────────▼──────────┐
          │   LAYER 2: EMBED    │  DeBERTa-v3 classifier · VAE anomaly detector
          └──────────┬──────────┘
                     │
          ┌──────────▼──────────┐
          │   LAYER 3: ENSEMBLE │  XGBoost meta-learner · NetworkX session GNN
          └──────────┬──────────┘
                     │
          ┌──────────▼──────────┐
          │   LAYER 4: POLICY   │  Groq LLM judge (Llama 3.1 8B) · Rule-based fallback
          └──────────┬──────────┘
                     │
          ┌──────────▼──────────┐
          │   LAYER 5: AUDIT    │  Presidio PII scanner · Audit logging
          └──────────┬──────────┘
                     │
              Final Verdict
          BLOCK · FLAG · PASS
```

| Layer | Component | Technology | Fallback |
|:-----:|-----------|------------|----------|
| 1 | Input sanitisation + perplexity filter | Regex, entropy scoring | Always real |
| 2 | Embedding anomaly detection | DeBERTa-v3 (protectai), VAE | Keyword heuristics |
| 3 | Ensemble detection engine | XGBoost (8 features), NetworkX GNN | Weighted sum |
| 4 | Policy enforcement + LLM verifier | Groq (Llama 3.1 8B) | Rule-based thresholds |
| 5 | Output validation + audit logging | Microsoft Presidio | Random 4% PII flag |

---

## Dashboard

The operator dashboard has **7 tabs**:

| Tab | Description |
|-----|-------------|
| **Dashboard** | Live stats, threat log, attack distribution, system log |
| **Analyzer** | Single-prompt analysis with sample payloads and SHAP feature importance |
| **Batch** | Analyze up to 20 prompts simultaneously |
| **Threat Intel** | Live threat intelligence feed + attack simulator |
| **Pipeline** | Detailed breakdown of all 5 security layers |
| **ML Metrics** | Confusion matrix, precision/recall/F1, detection rates by attack type |
| **Config** | Live threshold tuning, MITRE ATT&CK coverage, feedback submission |

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze` | Analyze a single text through all 5 layers |
| `POST` | `/api/batch` | Batch analyze up to 20 texts |
| `GET` | `/api/stats` | Live metrics + model status |
| `GET` | `/api/events` | Recent threat detections |
| `GET` | `/api/threat-intel` | Threat intelligence feed |
| `POST` | `/api/simulate-attack` | Fire a simulated attack |
| `GET/POST` | `/api/model-config` | Read/update detection thresholds |
| `POST` | `/api/feedback` | Submit corrections for retraining |
| `GET` | `/api/health` | System health check |
| `GET` | `/docs` | Interactive Swagger API docs |

---

## Project Structure

```
SentinelLLM/
├── backend/
│   ├── __init__.py
│   ├── constants.py      # Regex patterns, keywords, MITRE ATT&CK mappings
│   ├── models.py          # ModelRegistry — DeBERTa, VAE, XGBoost, Presidio, Groq
│   └── main.py            # FastAPI app, 5-layer pipeline, all API routes
├── frontend/
│   └── index.html         # Single-file operator dashboard (7 tabs)
├── scripts/
│   ├── __init__.py
│   └── train.py           # Trains VAE + XGBoost on HuggingFace datasets
├── models/                # Generated by train.py (gitignored)
│   ├── vae.pt
│   └── xgb.pkl
├── .env.example           # Template for environment variables
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── run.py                 # Entry point — starts the server
```

---

## Training Data

| Dataset | Source | Samples |
|---------|--------|---------|
| `deepset/prompt-injections` | HuggingFace | ~1,600 |
| `jackhhao/jailbreak-classification` | HuggingFace | ~2,000 |
| Benign samples (label=0) | Included in above | ~50% |

The training script uses a 80/20 train/test split with stratification. XGBoost evaluation metrics are printed after training.

---

## Graceful Degradation

The server starts and works **even before training is complete**. Each layer falls back to simulation mode if its model weights are missing:

| Missing Component | Fallback Behaviour |
|-------------------|--------------------|
| `models/vae.pt` | Layer 2 VAE uses heuristic anomaly score |
| `models/xgb.pkl` | Layer 3 XGBoost uses weighted feature sum |
| `GROQ_API_KEY` not set | Layer 4 uses rule-based verdict logic |
| Presidio not installed | Layer 5 uses probabilistic PII flag (4%) |
| DeBERTa not downloadable | Layer 2 uses keyword density scoring |

The dashboard shows a **LIVE / SIM** chip for each model so you always know what's running.

---

## Configuration

Detection thresholds can be adjusted live via the **Config** tab or the API:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `layer1_perplexity_threshold` | 150.0 | Flag inputs with entropy score above this |
| `layer2_deberta_threshold` | 0.50 | Minimum DeBERTa score to flag as injection |
| `layer2_vae_threshold` | 2.5 | Minimum VAE reconstruction error for zero-day |
| `layer3_block_threshold` | 0.75 | Ensemble score above this → BLOCK |
| `layer3_flag_threshold` | 0.45 | Ensemble score above this → FLAG |

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Mapped Threat Type |
|:------------:|------|-------------------|
| T1190 | Exploit Public-Facing Application | prompt_injection |
| T1203 | Exploitation for Client Execution | zero_day_anomaly |
| T1562 | Impair Defenses | jailbreak |
| T1041 | Exfiltration Over C2 Channel | data_exfiltration |
| T1027 | Obfuscated Files or Information | high_perplexity |
| T1059 | Command and Scripting Interpreter | suspicious |
| T1566 | Phishing / Social Engineering | — |
| T1078 | Valid Accounts Abuse | — |

---

## Tech Stack

| Category | Technologies |
|----------|-------------|
| **Backend** | Python, FastAPI, Uvicorn, Pydantic |
| **ML Models** | PyTorch (VAE), HuggingFace Transformers (DeBERTa-v3), XGBoost, scikit-learn |
| **Graph Analysis** | NetworkX (session GNN) |
| **PII Detection** | Microsoft Presidio, spaCy |
| **LLM Integration** | Groq API (Llama 3.1 8B Instant) |
| **Frontend** | Vanilla HTML/CSS/JS (single-file dashboard) |

---

## License

This project is licensed under the [MIT License](LICENSE).
