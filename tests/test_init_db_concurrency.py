"""Regression: dashboard and worker call init_db() at the same time on startup.

In Postgres, two simultaneous `CREATE TABLE IF NOT EXISTS` collide on
pg_type_typname_nsp_index (db.py uses an advisory lock to serialize them).
"""
import multiprocessing as mp
import os
import pathlib
import tempfile

import pytest

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="requiere DATABASE_URL")


def _run(path: str, q) -> None:
    try:
        from core.db import init_db

        init_db(pathlib.Path(path))
        q.put("ok")
    except Exception as exc:  # noqa: BLE001 - the test reports the error type
        q.put(f"{type(exc).__name__}: {exc}")


@pytest.mark.parametrize("_round", range(3))
def test_concurrent_init_db_does_not_collide(_round):
    path = str(pathlib.Path(tempfile.gettempdir()) / f"race_test_{os.getpid()}_{_round}.db")
    q = mp.Queue()
    procs = [mp.Process(target=_run, args=(path, q)) for _ in range(4)]
    for p in procs:
        p.start()
    results = [q.get(timeout=120) for _ in procs]
    for p in procs:
        p.join(timeout=120)
    assert results == ["ok"] * 4, results
