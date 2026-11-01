"""
PostgreSQL: connection, schema and test isolation.

Production uses DATABASE_URL (external postgres). Tests reuse the same URL
with a `t_<hash>` schema per key (it used to be a SQLite file).
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
    """Resolves a config path relative to the repo root."""
    raw = (value or "").strip() or default
    path = Path(raw).expanduser()
    return path if path.is_absolute() else (REPO_ROOT / path)


# Tests: monkeypatch DB_PATH to a unique Path to isolate the schema.
# Production: None → public schema.
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
    """Isolation schema. None → public. Any other key → t_<sha1>."""
    if path is None:
        return "public"
    digest = hashlib.sha1(str(path).encode("utf-8")).hexdigest()[:16]
    return f"t_{digest}"


class Row:
    """Row with access by name and index, like sqlite3.Row.

    `SELECT AVG(a), AVG(b)` in Postgres names both columns `avg`; the
    index 0/1 still tells them apart.
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
    """Translates SQLite placeholders (`?`, `:name`) and INSERT OR IGNORE to Postgres."""
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
    """Minimal facade compatible with sqlite3.Connection (execute/commit/close)."""

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

    def executescript(self, script: str) -> list:
        """Applies the script statement by statement, each with its own savepoint.

        Without savepoints, a single failing statement aborts the whole transaction
        and the following ones die with InFailedSqlTransaction: the error seen was
        the one from the later statement, not the real one. The schema is idempotent
        and additive, so a one-off failure must not block the rest.
        """
        fallidas = []
        for stmt in split_sql(script):
            self._raw.execute("SAVEPOINT esquema_stmt")
            try:
                self._raw.execute(stmt)
                self._raw.execute("RELEASE SAVEPOINT esquema_stmt")
            except Exception as exc:
                self._raw.execute("ROLLBACK TO SAVEPOINT esquema_stmt")
                fallidas.append(
                    f"{type(exc).__name__}: {str(exc)[:120]} | {' '.join(stmt.split())[:100]}"
                )
        return fallidas

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
    """Opens Postgres. `path` isolates a test schema; None uses DB_PATH or public."""
    isolation = path if path is not None else DB_PATH
    schema = schema_name(isolation)
    raw = psycopg.connect(database_url(), row_factory=_row_factory)
    raw.execute("SET timezone TO 'UTC'")
    # Without a commit the session stays "idle in transaction" from the first SET:
    # it holds locks and, if something fails, any following statement dies with
    # InFailedSqlTransaction (that is how init_db broke on startup).
    raw.commit()
    if schema != "public":
        ident = sql.Identifier(schema)
        # `CREATE SCHEMA IF NOT EXISTS` is not atomic across sessions: dashboard and
        # worker start at once and the second one hits pg_namespace_nspname_index.
        # That UniqueViolation aborted the transaction and left the schema unapplied
        # (the "Warning: could not apply the schema" from the deploy).
        try:
            raw.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(ident))
            raw.commit()
        except psycopg.errors.UniqueViolation:
            raw.rollback()  # another session created it first: the schema exists anyway
        # public goes as fallback: the extensions (pg_trgm, unaccent) live there and
        # without it the gin_trgm_ops indexes of an isolated schema do not resolve.
        raw.execute(sql.SQL("SET search_path TO {}, public").format(ident))
        raw.commit()
    return PgConnection(raw)


def init_db(path: Path | str | None = None):
    """Creates the schema. Idempotent: schema.sql only uses IF NOT EXISTS.

    Dashboard and worker start at once and `CREATE TABLE IF NOT EXISTS` is not atomic
    with itself in Postgres: the second session hits `pg_type_typname_nsp_index`.
    Both are serialized with a session advisory lock (released only if the process dies).
    """
    isolation = path if path is not None else DB_PATH
    lock_key = f"vulnradar.init_db.{schema_name(isolation)}"
    conn = get_db(isolation)
    try:
        # DDL needs ACCESS EXCLUSIVE: if the worker is in the middle of a large
        # batch (enrich), waiting here hung the dashboard startup, which never got
        # to open the port. Better to fail fast and go on with the existing schema
        # (schema.sql is idempotent).
        conn.execute("SET lock_timeout = '10s'")
        # pg_trgm backs the schema's gin_trgm_ops indexes: without the extension the
        # whole script aborts and the DB stays empty (so the tests and the startup
        # warning failed). If the role cannot create it, it goes on and the real error shows.
        try:
            conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
            conn.commit()
        except Exception:
            conn.rollback()
        try:
            conn.execute("SELECT pg_advisory_lock(hashtext(?))", (lock_key,))
            try:
                fallidas = conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
                conn.commit()
                for falla in fallidas:
                    print(f"Warning: schema statement skipped ({falla})")
            finally:
                conn.execute("SELECT pg_advisory_unlock(hashtext(?))", (lock_key,))
                conn.commit()
        except Exception as exc:
            conn.rollback()
            print(f"Warning: could not apply the schema ({type(exc).__name__}: {exc}). Continuing with the current one.")
    finally:
        conn.close()
    return isolation


def ensure_cve_stub(conn, cve_id: str) -> None:
    """
    Minimal row in cves so signals (KEV/EPSS) are not lost for CVEs the sync
    has not brought yet. The enrichments FK requires the parent CVE.
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
    """Drops t_* schemas created by pytest. Does not touch public."""
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
