"""
CVE List V5 incremental sync tests. No network: the mirror is a real git repo
built in tmp_path and `clone_or_pull` is replaced by a stub.

Watermark = mirror HEAD SHA (not dateUpdated: a CVE can be republished
without moving its date).
"""
import json
import subprocess
from pathlib import Path

import pytest

from agents import sync_agent
from core.db import get_db, init_db

FIXTURES = Path(__file__).parent / "fixtures" / "cvelistV5"
MARK = "2000-01-01 00:00:00"  # sentinel synced_at: if it changes, the row was rewritten


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


def _payload(cve_id: str, description: str = "Test sync payload.") -> str:
    """Minimal CVE List V5 derived from the Phase 1 fixture."""
    data = json.loads((FIXTURES / "CVE-2026-0001.json").read_text(encoding="utf-8"))
    data["cveMetadata"]["cveId"] = cve_id
    data["containers"]["cna"]["descriptions"] = [{"lang": "en", "value": description}]
    return json.dumps(data, ensure_ascii=False, indent=2)


def _write_cve(repo: Path, cve_id: str, description: str = "Test sync payload.") -> Path:
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
    """Mini git repo that mimics the CVE List V5 mirror."""
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
    """The test mirror already exists and has no remote: nothing to clone or pull."""
    monkeypatch.setattr(sync_agent, "clone_or_pull", lambda path: "pull")


@pytest.fixture
def processed(monkeypatch):
    """Records which files reach process_cve_file without changing its behavior."""
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
def test_init_db_creates_sync_state_and_is_idempotent(db_path):
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


def test_first_run_without_watermark_processes_everything(mirror, db_path, no_pull):
    _write_cve(mirror, "CVE-2026-0001")
    _write_cve(mirror, "CVE-2026-0002")
    _commit_all(mirror, "dos cves")

    stats = _run(mirror, db_path)

    assert stats["mode"] == "full"
    assert stats["reason"] == "no watermark"
    assert stats["files"] == 2
    assert stats["processed"] == 2
    assert _cve_ids(db_path) == {"CVE-2026-0001", "CVE-2026-0002"}

    conn = get_db(db_path)
    try:
        assert sync_agent.get_state(conn, sync_agent.HEAD_KEY) == sync_agent.git_head(mirror)
        assert sync_agent.get_state(conn, sync_agent.SYNCED_AT_KEY)
    finally:
        conn.close()


def test_second_run_without_git_changes_processes_zero(mirror, db_path, no_pull, processed):
    _write_cve(mirror, "CVE-2026-0001")
    _commit_all(mirror, "un cve")
    first = _run(mirror, db_path)
    _mark_synced(db_path, "CVE-2026-0001")
    processed.clear()

    second = _run(mirror, db_path)

    assert second["mode"] == "incremental"
    assert second["reason"] == "HEAD unchanged"
    assert second["files"] == 0
    assert second["processed"] == 0
    assert processed == []
    assert second["new_head"] == first["new_head"]  # stable watermark
    assert _synced_at(db_path, "CVE-2026-0001") == MARK


def test_incremental_processes_only_the_delta_and_does_not_rewrite_old_ones(
    mirror, db_path, no_pull, processed
):
    _write_cve(mirror, "CVE-2026-0001", "Original description.")
    _write_cve(mirror, "CVE-2026-0002", "Original description.")
    _commit_all(mirror, "dos cves")
    _run(mirror, db_path)
    _mark_synced(db_path, "CVE-2026-0001", "CVE-2026-0002")
    processed.clear()

    _write_cve(mirror, "CVE-2026-0003", "CVE nuevo.")
    _write_cve(mirror, "CVE-2026-0001", "Republished description.")
    _commit_all(mirror, "un cve nuevo y uno modificado")

    stats = _run(mirror, db_path)

    assert stats["mode"] == "incremental"
    assert stats["reason"] == "git delta"
    assert stats["files"] == 2
    assert sorted(processed) == ["CVE-2026-0001.json", "CVE-2026-0003.json"]
    assert _cve_ids(db_path) == {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}

    # The untouched one keeps its row; the republished one was rewritten.
    assert _synced_at(db_path, "CVE-2026-0002") == MARK
    assert _synced_at(db_path, "CVE-2026-0001") != MARK
    assert _synced_at(db_path, "CVE-2026-0003") != MARK


def test_full_rewrites_everything_even_with_watermark(mirror, db_path, no_pull, processed):
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


def test_delta_ignores_files_that_are_not_cves(mirror, db_path, no_pull, processed):
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

    # The full walk must not look at cves/delta.json either.
    full = _run(mirror, db_path, full=True)
    assert full["files"] == 1
    assert full["processed"] == 1


def test_invalid_json_returns_false_and_the_rest_continues(mirror, db_path, no_pull):
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


def test_unknown_watermark_falls_back_to_full_without_exploding(mirror, db_path, no_pull):
    """If the mirror was re-cloned, the stored SHA no longer exists: degrade to full."""
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
    assert stats["reason"] == "delta unavailable"
    assert stats["processed"] == 1


def test_without_watermark_and_populated_db_recovers_full_catalog(mirror, db_path, no_pull, processed):
    """Existing demo/stub/partial rows are not evidence of a completed import."""
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

    assert stats["mode"] == "full"
    assert stats["reason"] == "no watermark"
    assert stats["files"] == 1
    assert processed == ["CVE-2026-0001.json"]
    conn = get_db(db_path)
    try:
        assert sync_agent.get_state(conn, sync_agent.HEAD_KEY) == sync_agent.git_head(mirror)
    finally:
        conn.close()


def test_without_watermark_ignores_partial_pull_delta(mirror, db_path, monkeypatch, processed):
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

    assert stats["mode"] == "full"
    assert stats["reason"] == "no watermark"
    assert stats["processed"] == 2
    assert set(processed) == {"CVE-2026-0001.json", "CVE-2026-0002.json"}
    assert _cve_ids(db_path) == {"CVE-2026-0001", "CVE-2026-0002"}


def test_interrupted_initial_import_is_recovered(mirror, db_path, no_pull, monkeypatch):
    _write_cve(mirror, "CVE-2026-0001")
    _write_cve(mirror, "CVE-2026-0002")
    _commit_all(mirror, "two records")
    original = sync_agent.process_cve_file

    def interrupted(path, conn):
        if Path(path).name == "CVE-2026-0002.json":
            raise RuntimeError("interrupted initial import")
        return original(path, conn)

    with monkeypatch.context() as patch:
        patch.setattr(sync_agent, "COMMIT_EVERY", 1)
        patch.setattr(sync_agent, "process_cve_file", interrupted)
        with pytest.raises(RuntimeError, match="interrupted"):
            _run(mirror, db_path)
    assert _cve_ids(db_path) == {"CVE-2026-0001"}
    assert _run(mirror, db_path)["processed"] == 2
    assert _cve_ids(db_path) == {"CVE-2026-0001", "CVE-2026-0002"}


def test_clone_or_pull_resets_if_origin_rewrites_history(tmp_path):
    """CVE List V5 sometimes force-pushes main: the shallow clone becomes unrelated."""
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


def test_cli_full_is_opt_in_and_default_is_incremental():
    assert sync_agent.build_parser().parse_args([]).full is False
    assert sync_agent.build_parser().parse_args(["--full"]).full is True
    args = sync_agent.build_parser().parse_args(["--cve-list-path", "x", "--db-path", "y"])
    assert (args.cve_list_path, args.db_path) == ("x", "y")
