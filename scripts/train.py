"""
SentinelLLM — Training script
Trains the VAE (Layer 2 anomaly detector) and XGBoost (Layer 3 ensemble)
on real prompt-injection data from HuggingFace.

Usage:
    python scripts/train.py

Output:
    models/vae.pt    — VAE weights
    models/xgb.pkl   — XGBoost classifier
"""

import sys
import os
import re
import math
import pickle
import numpy as np
import torch
import torch.nn as nn
from pathlib import Path
from tqdm import tqdm

# Allow imports from project root
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.models import VAE
from backend.constants import INJECTION_PATTERNS, ZERO_DAY_PATTERNS, INJECTION_KEYWORDS

MODELS_DIR = ROOT / "models"
MODELS_DIR.mkdir(exist_ok=True)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Device: {DEVICE}\n")


# ── 1. Dataset ────────────────────────────────────────────────────────────────

def load_data():
    from datasets import load_dataset, concatenate_datasets, Dataset

    print("Loading datasets...")

    # Primary: deepset/prompt-injections (label: 0=benign, 1=injection)
    ds1 = load_dataset("deepset/prompt-injections", split="train")

    # Secondary: additional jailbreak samples
    try:
        ds2_raw = load_dataset("jackhhao/jailbreak-classification", split="train")
        # Map to same schema: text + label (1=injection/jailbreak, 0=benign)
        def remap(ex):
            return {"text": ex["prompt"], "label": 1 if ex["type"] == "jailbreak" else 0}
        ds2 = ds2_raw.map(remap, remove_columns=ds2_raw.column_names)
        ds1 = concatenate_datasets([ds1, ds2])
    except Exception as e:
        print(f"  Note: could not load secondary dataset ({e}), continuing with primary only")

    texts  = ds1["text"]
    labels = np.array(ds1["label"], dtype=np.int32)

    n_pos = int(labels.sum())
    n_neg = len(labels) - n_pos
    print(f"  Total: {len(texts)} samples  |  Injections: {n_pos}  |  Benign: {n_neg}\n")
    return texts, labels


# ── 2. DeBERTa embeddings + scores ───────────────────────────────────────────

def extract_embeddings(texts, batch_size=16):
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    model_name = "protectai/deberta-v3-base-prompt-injection-v2"
    print(f"Loading DeBERTa ({model_name})...")
    tok   = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    model.to(DEVICE).eval()

    all_emb   = []
    all_score = []

    print("Extracting embeddings...")
    for i in tqdm(range(0, len(texts), batch_size)):
        batch = list(texts[i : i + batch_size])
        inputs = tok(
            batch, return_tensors="pt",
            truncation=True, max_length=256, padding=True
        ).to(DEVICE)
        with torch.no_grad():
            out   = model(**inputs, output_hidden_states=True)
            probs = torch.softmax(out.logits, dim=-1)[:, 1].cpu().numpy()
            embs  = out.hidden_states[-1][:, 0, :].cpu().numpy()
        all_emb.extend(embs)
        all_score.extend(probs)

    # Free GPU memory
    del model
    torch.cuda.empty_cache() if DEVICE.type == "cuda" else None

    return np.array(all_emb), np.array(all_score)


# ── 3. VAE training ───────────────────────────────────────────────────────────

def train_vae(embeddings: np.ndarray, labels: np.ndarray, epochs=60):
    """Train VAE on benign-only embeddings."""
    benign_emb = embeddings[labels == 0]
    print(f"\nTraining VAE on {len(benign_emb)} benign embeddings...")

    vae = VAE(input_dim=768, hidden_dim=256, latent_dim=64)
    # Train on CPU to keep GPU free for DeBERTa (already freed)
    vae.train()
    opt = torch.optim.Adam(vae.parameters(), lr=1e-3, weight_decay=1e-5)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)
    X = torch.tensor(benign_emb, dtype=torch.float32)

    for epoch in range(1, epochs + 1):
        perm = torch.randperm(len(X))
        total = 0.0
        for i in range(0, len(X), 64):
            batch = X[perm[i : i + 64]]
            opt.zero_grad()
            recon, mu, logvar = vae(batch)
            recon_loss = nn.functional.mse_loss(recon, batch)
            kl_loss    = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp())
            loss = recon_loss + 0.001 * kl_loss
            loss.backward()
            opt.step()
            total += loss.item()
        scheduler.step()
        if epoch % 10 == 0:
            print(f"  Epoch {epoch:3d}/{epochs}  loss={total:.4f}")

    vae.eval()
    return vae


def compute_vae_errors(vae: VAE, embeddings: np.ndarray, batch_size=128) -> np.ndarray:
    X = torch.tensor(embeddings, dtype=torch.float32)
    errors = []
    with torch.no_grad():
        for i in range(0, len(X), batch_size):
            batch = X[i : i + batch_size]
            recon, _, _ = vae(batch)
            err = torch.mean((recon - batch) ** 2, dim=-1).numpy()
            errors.extend(err)
    return np.array(errors)


# ── 4. Layer 1 feature extraction ────────────────────────────────────────────

def char_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    t = len(s)
    return -sum((v / t) * math.log2(v / t) for v in freq.values())


def l1_features(texts) -> np.ndarray:
    print("\nComputing Layer 1 features...")
    rows = []
    for text in tqdm(texts):
        tl  = text.lower()
        inj  = float(any(re.search(p, tl, re.IGNORECASE) for p in INJECTION_PATTERNS))
        zday = float(any(re.search(p, text, re.IGNORECASE) for p in ZERO_DAY_PATTERNS))
        ent  = char_entropy(text)
        perp = min(ent * 40 / 300, 1.0)
        kws  = sum(1 for k in INJECTION_KEYWORDS if k in tl)
        rows.append([
            inj,
            zday,
            min(ent / 8, 1.0),
            perp,
            min(kws / 5, 1.0),
            min(len(text) / 500, 1.0),
        ])
    return np.array(rows, dtype=np.float32)


# ── 5. XGBoost training ───────────────────────────────────────────────────────

def train_xgboost(l1_feats, deberta_scores, vae_errors, labels):
    import xgboost as xgb
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix

    X = np.column_stack([
        l1_feats,
        deberta_scores.reshape(-1, 1),
        vae_errors.reshape(-1, 1),
    ])
    y = labels

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\nTraining XGBoost on {len(X_train)} samples...")
    clf = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        random_state=42,
        verbosity=0,
    )
    clf.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    y_pred = clf.predict(X_test)
    print("\n=== XGBoost Test Results ===")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Injection"]))

    cm = confusion_matrix(y_test, y_pred)
    print("Confusion matrix (rows=actual, cols=predicted):")
    print(f"  TN={cm[0,0]}  FP={cm[0,1]}")
    print(f"  FN={cm[1,0]}  TP={cm[1,1]}")

    return clf


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # 1. Data
    texts, labels = load_data()

    # 2. DeBERTa embeddings
    embeddings, deberta_scores = extract_embeddings(texts)

    # 3. VAE
    vae = train_vae(embeddings, labels)
    vae_errors = compute_vae_errors(vae, embeddings)

    vae_path = MODELS_DIR / "vae.pt"
    torch.save(vae.state_dict(), vae_path)
    print(f"\nVAE saved -> {vae_path}")

    # 4. Layer 1 features
    l1 = l1_features(texts)

    # 5. XGBoost
    xgb_model = train_xgboost(l1, deberta_scores, vae_errors, labels)
    xgb_path = MODELS_DIR / "xgb.pkl"
    with open(xgb_path, "wb") as f:
        pickle.dump(xgb_model, f)
    print(f"XGBoost saved -> {xgb_path}")

    print("\n[OK] Training complete. Run 'python run.py' to start the server.")


if __name__ == "__main__":
    main()
