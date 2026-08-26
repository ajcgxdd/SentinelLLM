"""
SentinelLLM — Launcher
Usage: python run.py
Then open: http://localhost:8000
"""
import os, sys
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

# Load .env before anything else
from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

from fastapi.staticfiles import StaticFiles
import backend.main as app_module

app = app_module.app
app.mount("/static", StaticFiles(directory=str(ROOT / "frontend")), name="static")

if __name__ == "__main__":
    import uvicorn

    groq_set = bool(os.environ.get("GROQ_API_KEY"))
    models_ready = (ROOT / "models" / "vae.pt").exists() and (ROOT / "models" / "xgb.pkl").exists()

    print("\n" + "="*62)
    print("  SentinelLLM v2.0 -- Multi-Layer AI Security Framework")
    print("="*62)
    print(f"  Models trained : {'YES' if models_ready else 'NO -- run: python scripts/train.py'}")
    print(f"  Groq API key   : {'SET' if groq_set else 'NOT SET -- Layer 4 will use rule-based fallback'}")
    print(f"  Dashboard      : http://localhost:8000")
    print(f"  API docs       : http://localhost:8000/docs")
    print("="*62 + "\n")

    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="warning",
    )
