"""
Worker autónomo: sync → enrich → score → alert, en loop.

No requiere comandos a mano. Intervalo: SYNC_INTERVAL_MINUTES (default 15).
Uso:
    python scripts/run_worker.py
    python scripts/run_worker.py --once
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.db import get_db, init_db

DEFAULT_INTERVAL = 15
KEEP_EVENTS = 400


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log_event(agent: str, event_type: str, details: str, status: str = "SUCCESS") -> None:
    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO agent_events (agent, event_type, details, status)
            VALUES (?, ?, ?, ?)
            """,
            (agent, event_type, details[:2000], status),
        )
        conn.execute(
            """
            DELETE FROM agent_events WHERE id NOT IN (
                SELECT id FROM agent_events ORDER BY id DESC LIMIT ?
            )
            """,
            (KEEP_EVENTS,),
        )
        conn.commit()
    finally:
        conn.close()
    print(f"[{_now()}] {agent} {event_type} {status} {details}", flush=True)


def _step(agent: str, event_type: str, fn):
    log_event(agent, event_type, "start", "RUNNING")
    try:
        result = fn()
        log_event(agent, event_type, str(result)[:1500], "SUCCESS")
        return result
    except Exception as exc:
        log_event(agent, event_type, f"{exc}\n{traceback.format_exc()[-800:]}", "ERROR")
        print(traceback.format_exc(), flush=True)
        return None


def run_cycle() -> dict:
    """Una pasada completa. Cada paso loguea; un fallo no cancela los siguientes."""
    init_db()
    summary = {}

    def do_sync():
        from agents.sync_agent import sync

        return sync(full=False)

    def do_enrich():
        from agents.enrichment_agent import run as enrich

        return enrich()

    def do_score():
        from agents.scoring_agent import run as score

        score()
        return "ok"

    def do_alert():
        from agents.alert_agent import run as alert

        return alert()

    summary["sync"] = _step("sync", "SYNC", do_sync)
    summary["enrich"] = _step("enrich", "ENRICH", do_enrich)
    summary["score"] = _step("score", "SCORE", do_score)
    summary["alert"] = _step("alert", "ALERT", do_alert)
    failed = [name for name, value in summary.items() if value is None]
    if failed:
        log_event("worker", "CYCLE", "falló: " + ",".join(failed), "ERROR")
    else:
        log_event("worker", "CYCLE", "ciclo completo", "SUCCESS")
    return summary


def interval_seconds() -> int:
    raw = os.getenv("SYNC_INTERVAL_MINUTES", str(DEFAULT_INTERVAL))
    try:
        minutes = float(raw)
    except ValueError:
        minutes = DEFAULT_INTERVAL
    return max(60, int(minutes * 60))


def loop() -> int:
    init_db()
    wait = interval_seconds()
    log_event("worker", "START", f"intervalo {wait}s", "INFO")
    while True:
        run_cycle()
        print(f"[{_now()}] sleep {wait}s", flush=True)
        time.sleep(wait)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Worker autónomo Humo vs Miedo")
    parser.add_argument("--once", action="store_true", help="Un ciclo y sale (tests / debug)")
    args = parser.parse_args(argv)
    if args.once:
        run_cycle()
        return 0
    return loop()


if __name__ == "__main__":
    raise SystemExit(main())
