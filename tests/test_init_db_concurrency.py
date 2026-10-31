"""Regresión: dashboard y worker llaman init_db() a la vez al arrancar.

En Postgres, dos `CREATE TABLE IF NOT EXISTS` simultáneos chocan en
pg_type_typname_nsp_index (db.py usa un advisory lock para serializarlos).
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
    except Exception as exc:  # noqa: BLE001 - el test reporta el tipo de error
        q.put(f"{type(exc).__name__}: {exc}")


@pytest.mark.parametrize("_round", range(3))
def test_init_db_concurrente_no_choca(_round):
    path = str(pathlib.Path(tempfile.gettempdir()) / f"race_test_{os.getpid()}_{_round}.db")
    q = mp.Queue()
    procs = [mp.Process(target=_run, args=(path, q)) for _ in range(4)]
    for p in procs:
        p.start()
    results = [q.get(timeout=120) for _ in procs]
    for p in procs:
        p.join(timeout=120)
    assert results == ["ok"] * 4, results
