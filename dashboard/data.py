"""
Carga y filtrado de scores para el dashboard.

Módulo puro (sqlite3 + stdlib, sin Streamlit ni pandas): la UI se testea con
pytest sin levantar el runtime de Streamlit.
"""

CATEGORIES = ("Overhyped", "Earned the hype", "Sleeper", "Quiet")

# Claves de cada fila, en el orden en que las consume la UI.
SCORE_COLUMNS = (
    "cve_id", "hype", "reality", "category", "calculated_at",
    "description", "cvss_score", "cvss_severity", "published",
    "tone_score", "media_count", "in_kev", "epss", "poc_count",
    "branding", "brand_name", "alertas", "alertado",
)

# `scores` tiene UNIQUE(cve_id): un solo score vigente por CVE y el JOIN
# directo alcanza. El LEFT JOIN conserva los CVEs todavía sin enriquecer.
SELECT_SCORES_BASE = """
    SELECT s.cve_id, s.hype, s.reality, s.category, s.calculated_at,
           c.description, c.cvss_score, c.cvss_severity, c.published,
           e.tone_score, e.media_count, e.in_kev, e.epss, e.poc_count,
           e.branding, e.brand_name
    FROM scores s
    JOIN cves c ON c.cve_id = s.cve_id
    LEFT JOIN enrichments e ON e.cve_id = s.cve_id
"""

SELECT_SCORES = SELECT_SCORES_BASE + "    ORDER BY s.calculated_at DESC\n"


def has_alerts_table(conn) -> bool:
    """`alerts_sent` es de la Fase 4: una base vieja puede no tenerla."""
    return _has_table(conn, "alerts_sent")


def load_alert_counts(conn) -> dict:
    """Cantidad de alertas enviadas por CVE. Sin tabla, ningún CVE está alertado."""
    if not has_alerts_table(conn):
        return {}
    rows = conn.execute(
        "SELECT cve_id, COUNT(*) FROM alerts_sent GROUP BY cve_id"
    ).fetchall()
    return {row[0]: int(row[1]) for row in rows}


def load_scores(conn, since=None, until=None) -> list:
    """
    Scores vigentes con su CVE y su enrichment.

    Base vacía -> lista vacía (no excepción): la UI decide el empty state.
    Se leen los nombres del cursor para no depender del row_factory del caller.
    El rango se filtra en SQL: con ~400k scores, traer todo y recortar en Python
    costaba ~9 s por request.
    """
    clauses: list[str] = []
    params: list[str] = []
    if since:
        clauses.append("date(coalesce(c.published, s.calculated_at)) >= date(?)")
        params.append(str(since)[:10])
    if until:
        clauses.append("date(coalesce(c.published, s.calculated_at)) <= date(?)")
        params.append(str(until)[:10])
    sql = SELECT_SCORES_BASE
    if clauses:
        sql += "    WHERE " + " AND ".join(clauses) + "\n"
    sql += "    ORDER BY s.calculated_at DESC\n"

    alerts = load_alert_counts(conn)
    cursor = conn.execute(sql, params)
    names = [column[0] for column in cursor.description]

    result = []
    for raw in cursor.fetchall():
        row = dict(zip(names, raw))
        count = alerts.get(row["cve_id"], 0)
        row["alertas"] = count
        row["alertado"] = count > 0
        result.append(row)
    return result



def filter_scores(
    rows,
    categories=None,
    min_hype=None,
    min_reality=None,
    severities=None,
    since=None,
    until=None,
) -> list:
    """
    Filtro puro sobre las filas de `load_scores`.

    `categories` vacío o None = sin filtro de categoría. Los mínimos son
    opcionales: 0/None no filtran. Un hype/reality NULL no pasa un mínimo > 0.
    `severities` compara cvss_severity en mayúsculas. Fechas sobre `published`
    (si falta, `calculated_at`); sin fecha la fila no pasa un rango activo.
    """
    wanted = {category for category in (categories or []) if category}
    wanted_sev = {str(item).upper() for item in (severities or []) if item}

    def below(value, minimum):
        return minimum is not None and minimum > 0 and (value is None or value < minimum)

    def in_range(row):
        if since is None and until is None:
            return True
        day = _as_date(row.get("published") or row.get("calculated_at"))
        if day is None:
            return False
        if since is not None and day < since:
            return False
        if until is not None and day > until:
            return False
        return True

    return [
        row for row in rows
        if (not wanted or row.get("category") in wanted)
        and (not wanted_sev or str(row.get("cvss_severity") or "").upper() in wanted_sev)
        and not below(row.get("hype"), min_hype)
        and not below(row.get("reality"), min_reality)
        and in_range(row)
    ]


def daily_averages(rows) -> list:
    """Promedio de hype/reality por día de publicación (o calculated_at)."""
    buckets: dict[str, list] = {}
    for row in rows:
        day = _as_date(row.get("published") or row.get("calculated_at"))
        if day is None:
            continue
        key = day.isoformat()
        buckets.setdefault(key, []).append(row)

    series = []
    for key in sorted(buckets):
        group = buckets[key]
        hypes = [row["hype"] for row in group if row.get("hype") is not None]
        realities = [row["reality"] for row in group if row.get("reality") is not None]
        series.append({
            "date": key,
            "hype": round(sum(hypes) / len(hypes), 2) if hypes else None,
            "reality": round(sum(realities) / len(realities), 2) if realities else None,
            "n": len(group),
        })
    return series


def load_mentions(conn, cve_id: str) -> list:
    if not _has_table(conn, "media_mentions"):
        return []
    cursor = conn.execute(
        """
        SELECT url, title, source, published
        FROM media_mentions
        WHERE cve_id = ?
        ORDER BY published DESC, created_at DESC
        """,
        (cve_id,),
    )
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, raw)) for raw in cursor.fetchall()]


def load_agent_stats(conn) -> dict:
    """Números reales de la DB para el panel de agentes (sin telemetría live)."""
    def count(sql, default=0):
        try:
            row = conn.execute(sql).fetchone()
            return int(row[0] if row and row[0] is not None else default)
        except Exception:
            return default

    n_cves = count("SELECT COUNT(*) FROM cves")
    n_enrich = count("SELECT COUNT(*) FROM enrichments")
    n_scores = count("SELECT COUNT(*) FROM scores")
    n_alerts = count("SELECT COUNT(*) FROM alerts_sent") if _has_table(conn, "alerts_sent") else 0
    avg_row = conn.execute("SELECT AVG(hype), AVG(reality) FROM scores").fetchone()
    avg_hype = round(float(avg_row[0] or 0), 1)
    avg_reality = round(float(avg_row[1] or 0), 1)

    sync_at = None
    if _has_table(conn, "sync_state"):
        row = conn.execute(
            "SELECT value FROM sync_state WHERE key = 'cvelist_synced_at'"
        ).fetchone()
        if row:
            sync_at = row[0]

    last = load_last_agent_status(conn)
    return {
        "cves": n_cves,
        "enrichments": n_enrich,
        "scores": n_scores,
        "alerts": n_alerts,
        "avg_hype": avg_hype,
        "avg_reality": avg_reality,
        "synced_at": sync_at,
        "agents": last,
    }


def load_recent_events(conn, limit: int = 15) -> list:
    if not _has_table(conn, "agent_events"):
        return []
    cursor = conn.execute(
        """
        SELECT ts, agent, event_type, details, status
        FROM agent_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, raw)) for raw in cursor.fetchall()]


def load_last_agent_status(conn) -> dict:
    """Último evento por agente (sync/enrich/score/alert)."""
    if not _has_table(conn, "agent_events"):
        return {}
    out = {}
    for agent in ("sync", "enrich", "score", "alert", "worker"):
        row = conn.execute(
            """
            SELECT ts, event_type, details, status
            FROM agent_events
            WHERE agent = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (agent,),
        ).fetchone()
        if row:
            out[agent] = {
                "ts": row[0],
                "event_type": row[1],
                "details": row[2],
                "status": row[3],
            }
    return out


def hype_components(row) -> list:
    """Barras 0-10 alineadas a la fórmula de hype (no inventa redes/Google)."""
    from core.normalizer import media_score, poc_score

    media = media_score(int(row.get("media_count") or 0))
    pocs = poc_score(int(row.get("poc_count") or 0))
    return [
        {"key": "cvss", "label": "CVSS", "value": float(row.get("cvss_score") or 0)},
        {"key": "media", "label": "Cobertura en medios", "value": media},
        {"key": "tone", "label": "Tono / titular", "value": float(row.get("tone_score") or 0)},
        {"key": "branding", "label": "Branding", "value": 10.0 if row.get("branding") else 0.0},
        {"key": "pocs", "label": "PoCs en GitHub", "value": pocs},
    ]


def guess_vuln_type(description: str | None) -> str:
    text = (description or "").lower()
    rules = (
        ("sql", "SQLi"),
        ("xss", "XSS"),
        ("cross-site", "XSS"),
        ("auth bypass", "AUTH BYPASS"),
        ("authentication bypass", "AUTH BYPASS"),
        ("privilege", "PRIV ESC"),
        ("rce", "RCE"),
        ("remote code", "RCE"),
        ("command injection", "RCE"),
        ("deserial", "RCE"),
        ("overflow", "RCE"),
        ("disclosure", "INFO DISCLOSURE"),
        ("open redirect", "OPEN REDIRECT"),
        ("ssrf", "SSRF"),
        ("dos", "DoS"),
        ("denial of service", "DoS"),
    )
    for needle, label in rules:
        if needle in text:
            return label
    return "—"


def _has_table(conn, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (name,),
    ).fetchone()
    return row is not None


def _as_date(value):
    from datetime import date, datetime

    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip().replace("Z", "")
    if not text:
        return None
    for size, fmt in ((19, "%Y-%m-%dT%H:%M:%S"), (19, "%Y-%m-%d %H:%M:%S"), (10, "%Y-%m-%d")):
        chunk = text[:size]
        try:
            return datetime.strptime(chunk, fmt).date()
        except ValueError:
            continue
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None
