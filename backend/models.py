"""
ModelRegistry — loads and serves all real ML models.

Each model degrades gracefully: if weights are missing or a dep is
unavailable, that layer falls back to the simulation path in main.py.
Run scripts/train.py once to produce models/vae.pt and models/xgb.pkl.
"""

import os
import json
import pickle
import numpy as np
import torch
import torch.nn as nn
from pathlib import Path

MODELS_DIR = Path(__file__).parent.parent / "models"


# ── VAE architecture ──────────────────────────────────────────────────────────

class VAE(nn.Module):
    """
    Variational Autoencoder trained on benign DeBERTa CLS embeddings.
    High reconstruction error → out-of-distribution (potential attack).
    """
    def __init__(self, input_dim: int = 768, hidden_dim: int = 256, latent_dim: int = 64):
        super().__init__()
        self.fc1      = nn.Linear(input_dim, hidden_dim)
        self.fc_mu    = nn.Linear(hidden_dim, latent_dim)
        self.fc_logvar= nn.Linear(hidden_dim, latent_dim)
        self.fc3      = nn.Linear(latent_dim, hidden_dim)
        self.fc4      = nn.Linear(hidden_dim, input_dim)

    def encode(self, x):
        h = torch.relu(self.fc1(x))
        return self.fc_mu(h), self.fc_logvar(h)

    def reparameterize(self, mu, logvar):
        std = torch.exp(0.5 * logvar)
        return mu + std * torch.randn_like(std)

    def decode(self, z):
        return self.fc4(torch.relu(self.fc3(z)))

    def forward(self, x):
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        return self.decode(z), mu, logvar

    @torch.no_grad()
    def reconstruction_error(self, x: torch.Tensor) -> float:
        recon, _, _ = self.forward(x)
        return torch.mean((recon - x) ** 2, dim=-1).item()


# ── Model Registry singleton ──────────────────────────────────────────────────

class ModelRegistry:
    """
    Singleton that loads all models once at server startup.
    Call registry.load() inside FastAPI @app.on_event("startup").
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded   = False
            cls._instance.deberta_ok = False
            cls._instance.vae_ok     = False
            cls._instance.xgb_ok     = False
            cls._instance.presidio_ok= False
            cls._instance.groq_ok    = False
        return cls._instance

    # ── Public: load everything ──────────────────────────────────────────────

    def load(self):
        if self._loaded:
            return
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"\n[ModelRegistry] Device: {self.device}")

        self._load_deberta()
        self._load_vae()
        self._load_xgboost()
        self._load_presidio()
        self._init_groq()

        self._loaded = True
        self._print_status()

    # ── Loaders ──────────────────────────────────────────────────────────────

    def _load_deberta(self):
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            model_name = "protectai/deberta-v3-base-prompt-injection-v2"
            print(f"[ModelRegistry] Loading DeBERTa ({model_name})...")
            self.deberta_tok   = AutoTokenizer.from_pretrained(model_name)
            self.deberta_model = AutoModelForSequenceClassification.from_pretrained(model_name)
            self.deberta_model.to(self.device).eval()
            self.deberta_ok = True
            print("[ModelRegistry] [OK] DeBERTa")
        except Exception as e:
            print(f"[ModelRegistry] [X] DeBERTa failed: {e}")
            self.deberta_ok = False

    def _load_vae(self):
        vae_path = MODELS_DIR / "vae.pt"
        self.vae = VAE()
        if vae_path.exists():
            try:
                self.vae.load_state_dict(torch.load(vae_path, map_location="cpu"))
                self.vae.to(self.device).eval()
                self.vae_ok = True
                print("[ModelRegistry] [OK] VAE")
            except Exception as e:
                print(f"[ModelRegistry] [X] VAE failed: {e}")
                self.vae_ok = False
        else:
            print("[ModelRegistry] [X] VAE -- run scripts/train.py first")
            self.vae_ok = False

    def _load_xgboost(self):
        xgb_path = MODELS_DIR / "xgb.pkl"
        if xgb_path.exists():
            try:
                with open(xgb_path, "rb") as f:
                    self.xgb_model = pickle.load(f)
                self.xgb_ok = True
                print("[ModelRegistry] [OK] XGBoost")
            except Exception as e:
                print(f"[ModelRegistry] [X] XGBoost failed: {e}")
                self.xgb_ok = False
        else:
            print("[ModelRegistry] [X] XGBoost -- run scripts/train.py first")
            self.xgb_ok = False

    def _load_presidio(self):
        try:
            from presidio_analyzer import AnalyzerEngine
            self.presidio = AnalyzerEngine()
            self.presidio_ok = True
            print("[ModelRegistry] [OK] Presidio")
        except Exception as e:
            print(f"[ModelRegistry] [X] Presidio failed: {e}")
            self.presidio_ok = False

    def _init_groq(self):
        try:
            from groq import Groq
            api_key = os.environ.get("GROQ_API_KEY", "")
            if not api_key:
                print("[ModelRegistry] [X] Groq -- GROQ_API_KEY not set in .env")
                self.groq_ok = False
                return
            self.groq = Groq(api_key=api_key)
            self.groq_ok = True
            print("[ModelRegistry] [OK] Groq (llama-3.1-8b-instant)")
        except Exception as e:
            print(f"[ModelRegistry] [X] Groq failed: {e}")
            self.groq_ok = False

    def _print_status(self):
        print("\n[ModelRegistry] Status:")
        print(f"  DeBERTa  : {'LIVE' if self.deberta_ok else 'SIMULATED'}")
        print(f"  VAE      : {'LIVE' if self.vae_ok else 'SIMULATED'}")
        print(f"  XGBoost  : {'LIVE' if self.xgb_ok else 'SIMULATED'}")
        print(f"  Presidio : {'LIVE' if self.presidio_ok else 'SIMULATED'}")
        print(f"  Groq LLM : {'LIVE' if self.groq_ok else 'RULE-BASED'}\n")

    # ── Inference methods ────────────────────────────────────────────────────

    def deberta_infer(self, text: str) -> tuple:
        """
        Returns (injection_prob: float, cls_embedding: np.ndarray | None).
        injection_prob ∈ [0, 1] — probability the input is an injection attack.
        cls_embedding is the 768-dim CLS token for VAE input.
        """
        if not self.deberta_ok:
            return None, None

        inputs = self.deberta_tok(
            text, return_tensors="pt",
            truncation=True, max_length=512
        ).to(self.device)

        with torch.no_grad():
            out = self.deberta_model(**inputs, output_hidden_states=True)
            prob = torch.softmax(out.logits, dim=-1)[0, 1].item()
            emb  = out.hidden_states[-1][:, 0, :].squeeze().cpu().numpy()

        return round(prob, 4), emb

    def vae_error(self, embedding: np.ndarray) -> float | None:
        """
        Returns VAE reconstruction error for the given embedding.
        Higher error → input is out-of-distribution → likely attack.
        """
        if not self.vae_ok or embedding is None:
            return None
        x = torch.tensor(embedding, dtype=torch.float32).unsqueeze(0).to(self.device)
        return round(self.vae.reconstruction_error(x), 4)

    def xgb_score(self, features: list) -> float | None:
        """Returns XGBoost threat probability for the 8-feature vector."""
        if not self.xgb_ok:
            return None
        X = np.array(features, dtype=np.float32).reshape(1, -1)
        return round(float(self.xgb_model.predict_proba(X)[0, 1]), 4)

    def llm_judge(self, text: str, scores: dict) -> dict | None:
        """
        Calls Groq (Llama 3.1 8B) with the full layer context.
        Returns {"verdict": "BLOCK|FLAG|PASS", "reason": str, "confidence": float}
        or None if Groq is unavailable.
        """
        if not self.groq_ok:
            return None

        prompt = (
            "You are a security classifier for an LLM firewall. "
            "Analyze the input text and multi-layer detection scores.\n\n"
            f"INPUT (truncated to 400 chars):\n{text[:400]}\n\n"
            "LAYER SCORES:\n"
            f"  Layer 1 — Pattern match: {scores['threat_type']}  "
            f"confidence={scores['l1_conf']:.3f}\n"
            f"  Layer 2 — DeBERTa injection score: {scores['deberta']:.3f}\n"
            f"  Layer 2 — VAE reconstruction error: {scores['vae']:.3f}\n"
            f"  Layer 3 — Ensemble fusion score: {scores['ensemble']:.3f}\n\n"
            "Based on these scores, give your verdict.\n"
            'Respond with ONLY a JSON object — no markdown, no preamble:\n'
            '{"verdict":"BLOCK|FLAG|PASS","reason":"one sentence","confidence":0.0}'
        )

        try:
            resp = self.groq.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=120,
            )
            raw = resp.choices[0].message.content.strip()
            # Strip markdown fences if model wraps in them
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            return json.loads(raw.strip())
        except Exception as e:
            print(f"[Groq] Error: {e}")
            return None

    def pii_scan(self, text: str) -> list[str]:
        """Returns list of detected PII entity types via Presidio."""
        if not self.presidio_ok:
            return []
        try:
            results = self.presidio.analyze(text=text, language="en")
            return list({r.entity_type for r in results})
        except Exception:
            return []


# Module-level singleton
registry = ModelRegistry()
