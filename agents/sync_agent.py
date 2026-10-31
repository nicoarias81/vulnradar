"""
Sync Agent — Sincroniza CVE List V5
Uso: python agents/sync_agent.py [--full] [--cve-list-path RUTA] [--db-path RUTA]

Sin --full hace sync incremental: compara el HEAD del mirror git con el
watermark guardado y procesa sólo los cves/**/*.json añadidos o modificados.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# `python agents/foo.py` pone agents/ en sys.path, no la raíz del repo.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.db import get_db, init_db, resolve_path
from core.normalizer import normalize_cve_list_v5

CVE_LIST_PATH = resolve_path(os.getenv("CVE_LIST_PATH", ""), "data/cvelistV5")
REPO_URL = "https://github.com/CVEProject/cvelistV5.git"

# El mirror real tiene cves/delta.json y cves/deltaLog.json en la raíz de cves/:
# sólo los subdirectorios de año contienen CVE List V5 por CVE.
CVES_SUBDIR = "cves"
CVE_FILE_SUFFIX = ".json"

COMMIT_EVERY = 1000
HEAD_KEY = "cvelist_head"
SYNCED_AT_KEY = "cvelist_synced_at"

# UPSERT en lugar de REPLACE: REPLACE borraría la fila de cves y rompería
# el FK de enrichments/scores.
UPSERT_SQL = """
    INSERT INTO cves (cve_id, published, last_modified, description,
                      cvss_score, cvss_vector, cvss_severity, raw_json)
    VALUES (:cve_id, :published, :last_modified, :description,
            :cvss_score, :cvss_vector, :cvss_severity, :raw_json)
    ON CONFLICT(cve_id) DO UPDATE SET
        published = excluded.published,
        last_modified = excluded.last_modified,
        description = excluded.description,
        cvss_score = excluded.cvss_score,
        cvss_vector = excluded.cvss_vector,
        cvss_severity = excluded.cvss_severity,
        raw_json = excluded.raw_json,
        synced_at = CURRENT_TIMESTAMP
"""


# --------------------------------------------------------------------------
# Estado del sync (watermark)
# --------------------------------------------------------------------------
def get_state(conn, key: str, default=None):
    row = conn.execute("SELECT value FROM sync_state WHERE key = ?", (key,)).fetchone()
    return row["value"] if row is not None else default


def set_state(conn, key: str, value: str) -> None:
    conn.execute(
        """
        INSERT INTO sync_state (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = CURRENT_TIMESTAMP
        """,
        (key, value),
    )


# --------------------------------------------------------------------------
# I/O de git (aislado para poder mockearlo en tests)
# --------------------------------------------------------------------------
def clone_or_pull(cve_list_path: Path) -> dict:
    """
    Clona el mirror la primera vez y después hace fetch + merge ff-only.

    Devuelve old_head / new_head y, si el diff se pudo calcular ANTES del
    merge, delta_files. En un clone shallow el commit viejo puede desaparecer
    después del merge: por eso el diff va antes.
    """
    if not cve_list_path.exists():
        print(f"Clonando CVE List V5 en {cve_list_path}...")
        subprocess.run(
            ["git", "clone", "--depth", "1", REPO_URL, str(cve_list_path)],
            check=True,
        )
        head = git_head(cve_list_path)
        return {"mode": "clone", "old_head": None, "new_head": head, "delta_files": None}

    print(f"Actualizando CVE List V5 en {cve_list_path}...")
    old = git_head(cve_list_path)
    subprocess.run(
        ["git", "-C", str(cve_list_path), "fetch", "--depth", "1", "origin"],
        check=True,
    )
    remote = git_rev_parse(cve_list_path, "FETCH_HEAD")
    if not remote or remote == old:
        return {"mode": "pull", "old_head": old, "new_head": old, "delta_files": []}

    delta_files = None
    try:
        delta_files = git_diff_cve_files(cve_list_path, old, remote)
    except subprocess.CalledProcessError as exc:
        print(f"Aviso: no se pudo diff {short_sha(old)}..{short_sha(remote)} ({exc}).")

    # --ff-only si se puede; si origin reescribió historia (forced update /
    # unrelated histories) alineamos el mirror al tip remoto. El diff ya se
    # calculó contra FETCH_HEAD; si no se pudo, sync() cae a full.
    try:
        subprocess.run(
            ["git", "-C", str(cve_list_path), "merge", "--ff-only", "FETCH_HEAD"],
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        print(
            f"Aviso: merge --ff-only falló ({exc}); origin reescribió historia. "
            "reset --hard FETCH_HEAD."
        )
        subprocess.run(
            ["git", "-C", str(cve_list_path), "reset", "--hard", "FETCH_HEAD"],
            check=True,
        )
    return {
        "mode": "pull",
        "old_head": old,
        "new_head": git_head(cve_list_path),
        "delta_files": delta_files,
    }


def git_rev_parse(cve_list_path: Path, ref: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(cve_list_path), "rev-parse", "--verify", "-q", ref],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def git_head(cve_list_path: Path) -> str:
    head = git_rev_parse(cve_list_path, "HEAD")
    if not head:
        raise RuntimeError(f"no hay HEAD en {cve_list_path}")
    return head


def git_diff_cve_files(cve_list_path: Path, old_sha: str, new_sha: str) -> list:
    """
    Archivos cves/**/*.json añadidos o modificados entre dos commits.
    Lanza CalledProcessError si old_sha no existe en el mirror (re-clone, GC).
    Los borrados se ignoran a propósito: no se borran filas locales.
    """
    result = subprocess.run(
        [
            "git", "-C", str(cve_list_path), "diff", "--name-only",
            "--no-renames", "--diff-filter=AM", old_sha, new_sha,
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return [cve_list_path / rel for rel in filter_cve_paths(result.stdout.splitlines())]


def filter_cve_paths(relative_paths) -> list:
    """Deja sólo rutas cves/**/*.json relativas al mirror (ignora README, .github, etc.)."""
    return [rel for rel in relative_paths if is_cve_file_path(rel)]


def is_cve_file_path(relative_path: str) -> bool:
    rel = relative_path.strip().replace("\\", "/")
    if not rel.startswith(f"{CVES_SUBDIR}/") or not rel.endswith(CVE_FILE_SUFFIX):
        return False
    # cves/delta.json quedaría justo un nivel bajo cves/: no es un CVE.
    return "/" in rel[len(CVES_SUBDIR) + 1:]


def iter_all_cve_files(cve_list_path: Path):
    """Recorrido completo del mirror: un JSON por CVE en los subdirectorios de año."""
    cves_dir = Path(cve_list_path) / CVES_SUBDIR
    if not cves_dir.is_dir():
        return
    for year_dir in sorted(p for p in cves_dir.iterdir() if p.is_dir()):
        for json_file in sorted(year_dir.rglob(f"*{CVE_FILE_SUFFIX}")):
            yield json_file


# --------------------------------------------------------------------------
# Procesamiento
# --------------------------------------------------------------------------
def process_cve_file(path: Path, conn) -> bool:
    """Normaliza un JSON de CVE List V5 y lo upsertea. False si se descarta."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error procesando {path}: {exc}")
        return False

    record = normalize_cve_list_v5(data)
    if record is None:
        return False

    conn.execute(UPSERT_SQL, record)
    return True


def plan_files(cve_list_path: Path, old_head, new_head: str, full: bool):
    """
    Decide qué archivos procesar. Devuelve (modo, archivos, motivo).
    modo = "full" | "incremental".
    """
    if full:
        return "full", list(iter_all_cve_files(cve_list_path)), "--full"

    if not old_head:
        return "full", list(iter_all_cve_files(cve_list_path)), "sin watermark"

    if old_head == new_head:
        # Pull sin commits nuevos: nada que procesar, el watermark no cambia.
        return "incremental", [], "HEAD sin cambios"

    try:
        return "incremental", git_diff_cve_files(cve_list_path, old_head, new_head), "delta git"
    except subprocess.CalledProcessError as exc:
        # El commit viejo ya no está (mirror re-clonado o historia reescrita).
        print(f"Aviso: delta imposible contra {short_sha(old_head)} ({exc}); se sincroniza todo.")
        return "full", list(iter_all_cve_files(cve_list_path)), "delta no disponible"


def process_files(files, conn) -> dict:
    """Upsertea cada archivo, commiteando cada COMMIT_EVERY para acotar la transacción."""
    processed = 0
    skipped = 0
    for index, path in enumerate(files, start=1):
        if process_cve_file(path, conn):
            processed += 1
        else:
            skipped += 1
        if index % COMMIT_EVERY == 0:
            conn.commit()
            print(f"Procesados {processed} CVEs ({index} archivos)...")
    conn.commit()
    return {"files": len(files), "processed": processed, "skipped": skipped}


def sync(full: bool = False, cve_list_path=None, db_path=None) -> dict:
    """
    Sincroniza CVE List V5 contra la DB.
    Devuelve stats: mode, reason, old_head, new_head, files, processed, skipped.
    """
    mirror = Path(cve_list_path) if cve_list_path is not None else CVE_LIST_PATH
    target_db = Path(db_path) if db_path is not None else None

    pull = clone_or_pull(mirror)
    if isinstance(pull, dict) and pull.get("new_head"):
        new_head = pull["new_head"]
        pull_delta = pull.get("delta_files")
        pull_old = pull.get("old_head")
    else:
        # Tests y stubs viejos pueden devolver "pull"/"clone".
        new_head = git_head(mirror)
        pull_delta = None
        pull_old = None

    # init_db es idempotente y garantiza sync_state en bases creadas antes de Fase 2.
    init_db(target_db)
    conn = get_db(target_db)
    try:
        old_head = get_state(conn, HEAD_KEY)
        n_cves = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        if (
            not full
            and not old_head
            and pull_old
            and pull_delta is not None
        ):
            mode, files, reason = "incremental", pull_delta, "sin watermark, delta del pull"
        elif not full and not old_head and n_cves:
            # Restart del worker con DB ya ingerida: no re-escanear 300k JSON.
            mode, files, reason = "incremental", [], "sin watermark, DB ya poblada"
        else:
            mode, files, reason = plan_files(mirror, old_head, new_head, full)
        print(
            f"Modo: {mode} ({reason}) | HEAD {short_sha(old_head or pull_old)} -> {short_sha(new_head)}"
        )

        stats = process_files(files, conn)
        set_state(conn, HEAD_KEY, new_head)
        set_state(conn, SYNCED_AT_KEY, _now_iso())
        conn.commit()
    finally:
        conn.close()

    print(
        f"Sync {mode} completado. Archivos: {stats['files']} | "
        f"upserts: {stats['processed']} | omitidos: {stats['skipped']}."
    )
    return {
        "mode": mode,
        "reason": reason,
        "old_head": old_head,
        "new_head": new_head,
        **stats,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sincroniza CVE List V5 (incremental por defecto).",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="recorre todos los JSON del mirror ignorando el watermark",
    )
    parser.add_argument(
        "--cve-list-path",
        default=None,
        help=f"ruta del mirror (default: $CVE_LIST_PATH o {CVE_LIST_PATH})",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="clave de aislamiento de schema (tests). Producción: DATABASE_URL",
    )
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    sync(full=args.full, cve_list_path=args.cve_list_path, db_path=args.db_path)
    return 0


def short_sha(sha) -> str:
    return (sha or "-")[:8]


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
