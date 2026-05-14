"""
ShieldAI v2 — Quick launcher
Run:  python run.py
Then open:  http://localhost:8000
"""
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from fastapi.staticfiles import StaticFiles
import backend.main as app_module

frontend_path = os.path.join(os.path.dirname(__file__), "frontend")
app_module.app.mount("/static", StaticFiles(directory=frontend_path), name="static")

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("  ShieldAI v2 — Multi-Layer AI Security Framework")
    print("="*60)
    print("  Open in browser:  http://localhost:8000")
    print("  API docs:         http://localhost:8000/docs")
    print("="*60 + "\n")
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="warning"
    )
