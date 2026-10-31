"""
PostgreSQL: conexión, esquema e aislamiento de tests.

Producción usa DATABASE_URL (postgres externo). Los tests reutilizan la misma
URL con un schema `t_<hash>` por clave (antes era un archivo SQLite).
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

import psycopg
from psycopg import sql

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "schema.sql"

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


# Tests: monkeypatch DB_PATH a un Path único para aislar el schema.
# Producción: None → schema public.
DB_PATH = None

_NAMED = re.compile(r"(?<!:):([a-zA-Z_][a-zA-Z0-9_]*)")
_INSERT_OR_IGNORE = re.compile(r"INSERT\s+OR\s+IGNORE\s+INTO", re.IGNORECASE)


def database_url() -> str:
    url = (os.getenv("DATABASE_URL") or "").strip()
    if not url:
        raise RuntimeError(
            "DATABASE_URL es obligatorio (PostgreSQL externo). "
            "Ejemplo: postgresql://user:pass@host:5432/humo"
        )
    return url


def schema_name(path) -> str:
    """Schema de aislamiento. None → public. Cualquier otra clave → t_<sha1>."""
    if path is None:
        return "public"
    digest = hashlib.sha1(str(path).encode("utf-8")).hexdigest()[:16]
    return f"t_{digest}"


class Row:
    """Fila con acceso por nombre e índice, como sqlite3.Row.

    `SELECT AVG(a), AVG(b)` en Postgres nombra las dos columnas `avg`; el
    índice 0/1 sigue distinguiéndolas.
    """

    __slots__ = ("_names", "_values", "_map")

    def __init__(self, pairs):
        pairs = list(pairs)
        self._names = [name for name, _ in pairs]
        self._values = [value for _, value in pairs]
        self._map = dict(pairs)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return self._map[key]

    def get(self, key, default=None):
        if isinstance(key, int):
            if 0 <= key < len(self._values):
                return self._values[key]
            return default
        return self._map.get(key, default)

    def __iter__(self):
        return iter(self._values)

    def keys(self):
        return self._names

    def values(self):
        return list(self._values)

    def __contains__(self, key):
        return key in self._map


def _row_factory(cursor):
    desc = cursor.description
    if desc is None:
        return lambda values: values
    names = [col.name for col in desc]

    def make(values):
        return Row(zip(names, values))

    return make


def adapt_sql(sql_text: str) -> str:
    """Traduce placeholders SQLite (`?`, `:name`) y INSERT OR IGNORE a Postgres."""
    if _INSERT_OR_IGNORE.search(sql_text):
        sql_text = _INSERT_OR_IGNORE.sub("INSERT INTO", sql_text, count=1)
        stripped = sql_text.rstrip()
        if stripped.endswith(";"):
            stripped = stripped[:-1].rstrip()
        sql_text = stripped + " ON CONFLICT DO NOTHING"
    sql_text = _NAMED.sub(r"%(\1)s", sql_text)
    return sql_text.replace("?", "%s")


def split_sql(script: str) -> list[str]:
    statements: list[str] = []
    buf: list[str] = []
    for line in script.splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            continue
        buf.append(line)
        if stripped.endswith(";"):
            stmt = "\n".join(buf).strip()
            if stmt:
                statements.append(stmt)
            buf = []
    rest = "\n".join(buf).strip()
    if rest:
        statements.append(rest)
    return statements


class PgConnection:
    """Fachada mínima compatible con sqlite3.Connection (execute/commit/close)."""

    def __init__(self, raw: psycopg.Connection):
        self._raw = raw

    def execute(self, query, params=None):
        adapted = adapt_sql(query)
        if params is None:
            return self._raw.execute(adapted)
        return self._raw.execute(adapted, params)

    def executemany(self, query, params_seq):
        adapted = adapt_sql(query)
        with self._raw.cursor() as cur:
            cur.executemany(adapted, params_seq)
            return cur

    def executescript(self, script: str) -> None:
        for stmt in split_sql(script):
            self._raw.execute(stmt)

    def commit(self):
        self._raw.commit()

    def rollback(self):
        self._raw.rollback()

    def close(self):
        try:
            self._raw.rollback()
        except Exception:
            pass
        self._raw.close()

    def cursor(self):
        return self._raw.cursor()


def get_db(path: Path | str | None = None) -> PgConnection:
    """Abre Postgres. `path` aísla un schema de test; None usa DB_PATH o public."""
    isolation = path if path is not None else DB_PATH
    schema = schema_name(isolation)
    raw = psycopg.connect(database_url(), row_factory=_row_factory)
    raw.execute("SET timezone TO 'UTC'")
    if schema != "public":
        ident = sql.Identifier(schema)
        raw.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(ident))
        raw.commit()
        raw.execute(sql.SQL("SET search_path TO {}").format(ident))
    return PgConnection(raw)


def init_db(path: Path | str | None = None):
    """Crea el esquema. Idempotente: schema.sql sólo usa IF NOT EXISTS."""
    isolation = path if path is not None else DB_PATH
    conn = get_db(isolation)
    try:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        conn.commit()
    finally:
        conn.close()
    return isolation


def ensure_cve_stub(conn, cve_id: str) -> None:
    """
    Fila mínima en cves para no perder señales (KEV/EPSS) de CVEs que el sync
    todavía no trajo. El FK de enrichments exige el CVE padre.
    """
    conn.execute(
        "INSERT INTO cves (cve_id) VALUES (?) ON CONFLICT (cve_id) DO NOTHING",
        (cve_id,),
    )


def has_table(conn, name: str) -> bool:
    row = conn.execute(
        """
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = current_schema() AND table_name = ?
        """,
        (name,),
    ).fetchone()
    return row is not None


def list_tables(conn) -> set[str]:
    rows = conn.execute(
        """
        SELECT table_name AS name FROM information_schema.tables
        WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'
        """
    ).fetchall()
    return {row["name"] for row in rows}


def table_columns(conn, name: str) -> set[str]:
    rows = conn.execute(
        """
        SELECT column_name AS name FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = ?
        """,
        (name,),
    ).fetchall()
    return {row["name"] for row in rows}


def table_indexes(conn, name: str) -> set[str]:
    rows = conn.execute(
        """
        SELECT indexname AS name FROM pg_indexes
        WHERE schemaname = current_schema() AND tablename = ?
        """,
        (name,),
    ).fetchall()
    return {row["name"] for row in rows}


def drop_test_schemas() -> None:
    """Borra schemas t_* creados por pytest. No toca public."""
    try:
        url = database_url()
    except RuntimeError:
        return
    with psycopg.connect(url, autocommit=True) as conn:
        rows = conn.execute(
            "SELECT nspname FROM pg_namespace WHERE nspname LIKE 't_%'"
        ).fetchall()
        for row in rows:
            name = row[0]
            conn.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(name))
            )


if __name__ == "__main__":
    init_db()
    print("PostgreSQL: esquema aplicado en", database_url().split("@")[-1])
