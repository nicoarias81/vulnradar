"""
Modelos de datos y helpers de base de datos
"""
import os
import sqlite3
from pathlib import Path

# Rutas ancladas al repo, no al cwd: los agentes se pueden lanzar desde cualquier lado.
REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "schema.sql"

# python-dotenv es opcional en runtime: sin .env se usan los defaults.
try:
    from dotenv import load_dotenv

    load_dotenv(REPO_ROOT / ".env")
except ImportError:  # pragma: no cover
    pass


def resolve_path(value: str, default: str) -> Path:
    """Resuelve una ruta de configuración relativa a la raíz del repo."""
    raw = (value or "").strip() or default
    path = Path(raw).expanduser()
    return path if path.is_absolute() else (REPO_ROOT / path)


# El entorno se lee al importar: DB_PATH=/tmp/x python -m core.db funciona.
DB_PATH = resolve_path(os.getenv("DB_PATH", ""), "data/humo.db")


def get_db(path: Path | str | None = None) -> sqlite3.Connection:
    """Abre (creando el directorio si falta) la base con foreign keys activas."""
    db_path = Path(path) if path is not None else DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path: Path | str | None = None) -> Path:
    """Crea el esquema. Idempotente: schema.sql sólo usa IF NOT EXISTS."""
    db_path = Path(path) if path is not None else DB_PATH
    conn = get_db(db_path)
    try:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        conn.commit()
    finally:
        conn.close()
    return db_path


def ensure_cve_stub(conn: sqlite3.Connection, cve_id: str) -> None:
    """
    Fila mínima en cves para no perder señales (KEV/EPSS) de CVEs que el sync
    todavía no trajo. Con PRAGMA foreign_keys=ON no se puede crear el
    enrichment sin su CVE padre.
    """
    conn.execute("INSERT OR IGNORE INTO cves (cve_id) VALUES (?)", (cve_id,))


if __name__ == "__main__":
    print(f"Base de datos inicializada en {init_db()}")
