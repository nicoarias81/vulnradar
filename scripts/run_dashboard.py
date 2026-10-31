"""Arranca el dashboard: init DB, seed de demo si hace falta, Streamlit."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.db import get_db, init_db
from scripts.seed_demo import seed


def _score_count() -> int:
    conn = get_db()
    try:
        row = conn.execute("SELECT COUNT(*) FROM scores").fetchone()
        return int(row[0])
    finally:
        conn.close()


def main() -> int:
    init_db()
    if os.getenv("SEED_DEMO", "1") != "0":
        print("Cargando / actualizando CVEs de demostración…")
        seed()
        print(f"scores en DB: {_score_count()}")

    os.execvp(
        "streamlit",
        [
            "streamlit", "run", "dashboard/app.py",
            "--server.port=8501",
            "--server.address=0.0.0.0",
            "--server.headless=true",
            "--browser.gatherUsageStats=false",
        ],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
