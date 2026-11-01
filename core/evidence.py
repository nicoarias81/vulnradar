"""Source-local observations and refresh status. No source overwrites another."""
from __future__ import annotations
import json


def observe(conn, cve_id, source, kind, external_id, *, url=None,
            event_date=None, trusted=False, payload=None):
    conn.execute("""
        INSERT INTO evidence (cve_id, source, kind, external_id, url, event_date, trusted, payload)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id, source, kind, external_id) DO UPDATE SET
            url=excluded.url, event_date=excluded.event_date, trusted=excluded.trusted,
            payload=excluded.payload, active=true, observed_at=CURRENT_TIMESTAMP
    """, (cve_id, source, kind, str(external_id), url, event_date, trusted,
          json.dumps(payload, ensure_ascii=False, default=str) if payload is not None else None))


def record_run(conn, source, status, details, version=None):
    conn.execute("INSERT INTO source_runs(source,status,version,details) VALUES (?,?,?,?)",
                 (source, status, version, json.dumps(details, default=str, ensure_ascii=False)))


def run_source(conn, source, fn, *, version=None):
    """A failing source rolls back its own work, then persists its error status."""
    conn.commit()
    try:
        result = fn()
        partial = isinstance(result, dict) and (result.get('paginas_fallidas') or result.get('truncated'))
        record_run(conn, source, 'PARTIAL' if partial else 'SUCCESS', result, version)
        conn.commit()
        return result
    except Exception as exc:
        conn.rollback()
        detail = {'error': type(exc).__name__, 'message': str(exc)[:500]}
        record_run(conn, source, 'ERROR', detail, version)
        conn.commit()
        return detail


def source_poc_count(conn, cve_id, count, source='github'):
    """Count source artifacts separately; the legacy count is a max, not a union."""
    if source not in ('github', 'exploitdb'):
        raise ValueError('Unsupported PoC source')
    field = source + '_poc_count'
    other = 'exploitdb_poc_count' if source == 'github' else 'github_poc_count'
    conn.execute(f"""
        INSERT INTO enrichments (cve_id, {field}, poc_count) VALUES (?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            {field}=excluded.{field},
            poc_count=CASE WHEN excluded.{field} > COALESCE(enrichments.{other},0)
                THEN excluded.{field} ELSE COALESCE(enrichments.{other},0) END,
            updated_at=CURRENT_TIMESTAMP
    """, (cve_id, max(0,int(count)), max(0,int(count))))
