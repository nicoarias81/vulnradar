"""
Tests del sync incremental de CVE List V5. Sin red: el mirror es un repo git
real armado en tmp_path y `clone_or_pull` se reemplaza por un stub.

Watermark = SHA de HEAD del mirror (no dateUpdated: un CVE se puede republicar
sin mover su fecha).
"""
import json
import subprocess
from pathlib import Path

import pytest

from agents import sync_agent
from core.db import get_db, init_db

FIXTURES = Path(__file__).parent / "fixtures" / "cvelistV5"
MARK = "2000-01-01 00:00:00"  # synced_at centinela: si cambia, la fila se reescribió


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _commit_all(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", message)


def _payload(cve_id: str, description: str = "Payload de prueba de sync.") -> str:
    """CVE List V5 mínimo derivado del fixture de Fase 1."""
    data = json.loads((FIXTURES / "CVE-2026-0001.json").read_text(encoding="utf-8"))
    data["cveMetadata"]["cveId"] = cve_id
    data["containers"]["cna"]["descriptions"] = [{"lang": "en", "value": description}]
    return json.dumps(data, ensure_ascii=False, indent=2)


def _write_cve(repo: Path, cve_id: str, description: str = "Payload de prueba de sync.") -> Path:
    path = repo / "cves" / "2026" / f"{cve_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_payload(cve_id, description), encoding="utf-8")
    return path


def _synced_at(db_path: Path, cve_id: str):
    conn = get_db(db_path)
    try:
        row = conn.execute("SELECT synced_at FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
        if row is None:
            return None
        value = row["synced_at"]
        if hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return str(value)[:19]
    finally:
        conn.close()


def _mark_synced(db_path: Path, *cve_ids: str) -> None:
    conn = get_db(db_path)
    try:
        for cve_id in cve_ids:
            conn.execute("UPDATE cves SET synced_at = ? WHERE cve_id = ?", (MARK, cve_id))
        conn.commit()
    finally:
        conn.close()


def _cve_ids(db_path: Path) -> set:
    conn = get_db(db_path)
    try:
        return {row["cve_id"] for row in conn.execute("SELECT cve_id FROM cves")}
    finally:
        conn.close()


def _run(mirror: Path, db_path: Path, full: bool = False) -> dict:
    return sync_agent.sync(full=full, cve_list_path=mirror, db_path=db_path)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
@pytest.fixture
def mirror(tmp_path) -> Path:
    """Mini repo git que imita el mirror de CVE List V5."""
    repo = tmp_path / "cvelistV5"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "sync-tests@example.com")
    _git(repo, "config", "user.name", "Sync Tests")
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "config", "core.autocrlf", "false")
    (repo / "README.md").write_text("# mirror de prueba\n", encoding="utf-8")
    _commit_all(repo, "init")
    return repo


@pytest.fixture
def db_path(tmp_path) -> Path:
    return tmp_path / "humo.db"


@pytest.fixture
def no_pull(monkeypatch):
    """El mirror del test ya existe y no tiene remoto: no hay nada que clonar/pullear."""
    monkeypatch.setattr(sync_agent, "clone_or_pull", lambda path: "pull")


@pytest.fixture
def processed(monkeypatch):
    """Registra qué archivos llegan a process_cve_file sin cambiar su comportamiento."""
    seen = []
    original = sync_agent.process_cve_file

    def wrapper(path, conn):
        seen.append(Path(path).name)
        return original(path, conn)

    monkeypatch.setattr(sync_agent, "process_cve_file", wrapper)
    return seen


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------
def test_init_db_crea_sync_state_y_es_idempotente(db_path):
    init_db(db_path)
    init_db(db_path)

    conn = get_db(db_path)
    try:
        from core.db import table_columns

        columns = table_columns(conn, "sync_state")
        assert {"key", "value", "updated_at"} <= columns
        sync_agent.set_state(conn, sync_agent.HEAD_KEY, "abc123")
        sync_agent.set_state(conn, sync_agent.HEAD_KEY, "def456")
        conn.commit()
        assert sync_agent.get_state(conn, sync_agent.HEAD_KEY) == "def456"
        assert sync_agent.get_state(conn, "no_existe") is None
    finally:
        conn.close()


def test_primera_corrida_sin_watermark_procesa_todo(mirror, db_path, no_pull):
    _write_cve(mirror, "CVE-2026-0001")
    _write_cve(mirror, "CVE-2026-0002")
    _commit_all(mirror, "dos cves")

    stats = _run(mirror, db_path)

    assert stats["mode"] == "full"
    assert stats["reason"] == "sin watermark"
    assert stats["files"] == 2
    assert stats["processed"] == 2
    assert _cve_ids(db_path) == {"CVE-2026-0001", "CVE-2026-0002"}

    conn = get_db(db_path)
    try:
        assert sync_agent.get_state(conn, sync_agent.HEAD_KEY) == sync_agent.git_head(mirror)
        assert sync_agent.get_state(conn, sync_agent.SYNCED_AT_KEY)
    finally:
        conn.close()


def test_segunda_corrida_sin_cambios_en_git_procesa_cero(mirror, db_path, no_pull, processed):
    _write_cve(mirror, "CVE-2026-0001")
    _commit_all(mirror, "un cve")
    first = _run(mirror, db_path)
    _mark_synced(db_path, "CVE-2026-0001")
    processed.clear()

    second = _run(mirror, db_path)

    assert second["mode"] == "incremental"
    assert second["reason"] == "HEAD sin cambios"
    assert second["files"] == 0
    assert second["processed"] == 0
    assert processed == []
    assert second["new_head"] == first["new_head"]  # watermark estable
    assert _synced_at(db_path, "CVE-2026-0001") == MARK


def test_incremental_procesa_solo_el_delta_y_no_reescribe_los_viejos(
    mirror, db_path, no_pull, processed
):
    _write_cve(mirror, "CVE-2026-0001", "Descripción original.")
    _write_cve(mirror, "CVE-2026-0002", "Descripción original.")
    _commit_all(mirror, "dos cves")
    _run(mirror, db_path)
    _mark_synced(db_path, "CVE-2026-0001", "CVE-2026-0002")
    processed.clear()

    _write_cve(mirror, "CVE-2026-0003", "CVE nuevo.")
    _write_cve(mirror, "CVE-2026-0001", "Descripción republicada.")
    _commit_all(mirror, "un cve nuevo y uno modificado")

    stats = _run(mirror, db_path)

    assert stats["mode"] == "incremental"
    assert stats["reason"] == "delta git"
    assert stats["files"] == 2
    assert sorted(processed) == ["CVE-2026-0001.json", "CVE-2026-0003.json"]
    assert _cve_ids(db_path) == {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}

    # El no tocado conserva su fila; el republicado se reescribió.
    assert _synced_at(db_path, "CVE-2026-0002") == MARK
    assert _synced_at(db_path, "CVE-2026-0001") != MARK
    assert _synced_at(db_path, "CVE-2026-0003") != MARK


def test_full_reescribe_todo_aunque_exista_watermark(mirror, db_path, no_pull, processed):
    _write_cve(mirror, "CVE-2026-0001")
    _write_cve(mirror, "CVE-2026-0002")
    _commit_all(mirror, "dos cves")
    _run(mirror, db_path)
    _mark_synced(db_path, "CVE-2026-0001", "CVE-2026-0002")
    processed.clear()

    stats = _run(mirror, db_path, full=True)

    assert stats["mode"] == "full"
    assert stats["reason"] == "--full"
    assert stats["files"] == 2
    assert sorted(processed) == ["CVE-2026-0001.json", "CVE-2026-0002.json"]
    assert _synced_at(db_path, "CVE-2026-0001") != MARK
    assert _synced_at(db_path, "CVE-2026-0002") != MARK


def test_delta_ignora_archivos_que_no_son_cves(mirror, db_path, no_pull, processed):
    _write_cve(mirror, "CVE-2026-0001")
    (mirror / "cves" / "delta.json").write_text('{"count": 0}', encoding="utf-8")
    _commit_all(mirror, "un cve y el indice delta")
    _run(mirror, db_path)
    processed.clear()

    (mirror / "README.md").write_text("# mirror de prueba (otra vez)\n", encoding="utf-8")
    (mirror / "cves" / "delta.json").write_text('{"count": 1}', encoding="utf-8")
    _commit_all(mirror, "solo README y delta.json")

    stats = _run(mirror, db_path)

    assert stats["mode"] == "incremental"
    assert stats["files"] == 0
    assert processed == []

    # El recorrido completo tampoco debe mirar cves/delta.json.
    full = _run(mirror, db_path, full=True)
    assert full["files"] == 1
    assert full["processed"] == 1


def test_json_invalido_devuelve_false_y_el_resto_continua(mirror, db_path, no_pull):
    path = mirror / "cves" / "2026" / "CVE-2026-9999.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ esto no es json", encoding="utf-8")
    _write_cve(mirror, "CVE-2026-0001")
    _commit_all(mirror, "un cve roto y uno sano")

    stats = _run(mirror, db_path)

    assert stats["processed"] == 1
    assert stats["skipped"] == 1
    assert _cve_ids(db_path) == {"CVE-2026-0001"}

    conn = get_db(db_path)
    try:
        assert sync_agent.process_cve_file(path, conn) is False
    finally:
        conn.close()


def test_watermark_desconocido_cae_a_full_sin_explotar(mirror, db_path, no_pull):
    """Si el mirror se re-clonó, el SHA guardado ya no existe: degradar a full."""
    _write_cve(mirror, "CVE-2026-0001")
    _commit_all(mirror, "un cve")
    _run(mirror, db_path)

    conn = get_db(db_path)
    try:
        sync_agent.set_state(conn, sync_agent.HEAD_KEY, "0" * 40)
        conn.commit()
    finally:
        conn.close()

    stats = _run(mirror, db_path)

    assert stats["mode"] == "full"
    assert stats["reason"] == "delta no disponible"
    assert stats["processed"] == 1


def test_sin_watermark_con_db_poblada_no_recorre_todo(mirror, db_path, no_pull, processed):
    """Reinicio del worker: la DB ya tiene CVEs, no hay que reingestar 300k JSON."""
    _write_cve(mirror, "CVE-2026-0001")
    _commit_all(mirror, "un cve")
    _run(mirror, db_path)
    processed.clear()

    conn = get_db(db_path)
    try:
        conn.execute("DELETE FROM sync_state WHERE key = ?", (sync_agent.HEAD_KEY,))
        conn.commit()
    finally:
        conn.close()

    stats = _run(mirror, db_path)

    assert stats["mode"] == "incremental"
    assert stats["reason"] == "sin watermark, DB ya poblada"
    assert stats["files"] == 0
    assert processed == []
    conn = get_db(db_path)
    try:
        assert sync_agent.get_state(conn, sync_agent.HEAD_KEY) == sync_agent.git_head(mirror)
    finally:
        conn.close()


def test_sin_watermark_usa_delta_del_pull(mirror, db_path, monkeypatch, processed):
    _write_cve(mirror, "CVE-2026-0001")
    _commit_all(mirror, "uno")
    extra = _write_cve(mirror, "CVE-2026-0002")
    _commit_all(mirror, "dos")
    head = sync_agent.git_head(mirror)
    monkeypatch.setattr(
        sync_agent,
        "clone_or_pull",
        lambda path: {
            "mode": "pull",
            "old_head": "a" * 40,
            "new_head": head,
            "delta_files": [extra],
        },
    )

    stats = _run(mirror, db_path)

    assert stats["mode"] == "incremental"
    assert stats["reason"] == "sin watermark, delta del pull"
    assert stats["processed"] == 1
    assert processed == ["CVE-2026-0002.json"]
    assert _cve_ids(db_path) == {"CVE-2026-0002"}


def test_clone_or_pull_reset_si_origin_reescribe_historia(tmp_path):
    """CVE List V5 a veces force-pushea main: el shallow clone queda unrelated."""
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "main")
    _git(origin, "config", "user.email", "sync-tests@example.com")
    _git(origin, "config", "user.name", "Sync Tests")
    _git(origin, "config", "commit.gpgsign", "false")
    _git(origin, "config", "core.autocrlf", "false")
    _write_cve(origin, "CVE-2026-0001")
    _commit_all(origin, "historia vieja")

    mirror = tmp_path / "mirror"
    subprocess.run(
        ["git", "clone", "--depth", "1", str(origin), str(mirror)],
        check=True,
        capture_output=True,
        text=True,
    )
    old = sync_agent.git_head(mirror)

    _git(origin, "checkout", "--orphan", "rewritten")
    for leftover in (origin / "cves").rglob("*.json"):
        leftover.unlink()
    _write_cve(origin, "CVE-2026-0002", "Historia reescrita.")
    _commit_all(origin, "historia nueva")
    _git(origin, "branch", "-M", "main")

    result = sync_agent.clone_or_pull(mirror)

    assert result["mode"] == "pull"
    assert result["old_head"] == old
    assert result["new_head"] != old
    assert result["new_head"] == sync_agent.git_head(mirror)
    assert (mirror / "cves" / "2026" / "CVE-2026-0002.json").exists()


def test_cli_full_es_opt_in_y_el_default_es_incremental():
    assert sync_agent.build_parser().parse_args([]).full is False
    assert sync_agent.build_parser().parse_args(["--full"]).full is True
    args = sync_agent.build_parser().parse_args(["--cve-list-path", "x", "--db-path", "y"])
    assert (args.cve_list_path, args.db_path) == ("x", "y")
