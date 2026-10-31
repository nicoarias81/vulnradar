"""
Carga y filtrado de scores para el dashboard.

Módulo puro (sqlite3 + stdlib, sin Streamlit ni pandas): la UI se testea con
pytest sin levantar el runtime de Streamlit.
"""

CATEGORIES = ("Overhyped", "Earned the hype", "Sleeper", "Quiet")

# Claves de cada fila, en el orden en que las consume la UI.
SCORE_COLUMNS = (
    "cve_id", "hype", "reality", "category", "calculated_at",
    "description", "cvss_score", "cvss_severity",
    "tone_score", "media_count", "in_kev", "epss", "poc_count",
    "branding", "brand_name", "alertas", "alertado",
)

# `scores` tiene UNIQUE(cve_id): un solo score vigente por CVE y el JOIN
# directo alcanza. El LEFT JOIN conserva los CVEs todavía sin enriquecer.
SELECT_SCORES = """
    SELECT s.cve_id, s.hype, s.reality, s.category, s.calculated_at,
           c.description, c.cvss_score, c.cvss_severity,
           e.tone_score, e.media_count, e.in_kev, e.epss, e.poc_count,
           e.branding, e.brand_name
    FROM scores s
    JOIN cves c ON c.cve_id = s.cve_id
    LEFT JOIN enrichments e ON e.cve_id = s.cve_id
    ORDER BY s.calculated_at DESC
"""


def has_alerts_table(conn) -> bool:
    """`alerts_sent` es de la Fase 4: una base vieja puede no tenerla."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'alerts_sent'"
    ).fetchone()
    return row is not None


def load_alert_counts(conn) -> dict:
    """Cantidad de alertas enviadas por CVE. Sin tabla, ningún CVE está alertado."""
    if not has_alerts_table(conn):
        return {}
    rows = conn.execute(
        "SELECT cve_id, COUNT(*) FROM alerts_sent GROUP BY cve_id"
    ).fetchall()
    return {row[0]: int(row[1]) for row in rows}


def load_scores(conn) -> list:
    """
    Scores vigentes con su CVE y su enrichment.

    Base vacía -> lista vacía (no excepción): la UI decide el empty state.
    Se leen los nombres del cursor para no depender del row_factory del caller.
    """
    alerts = load_alert_counts(conn)
    cursor = conn.execute(SELECT_SCORES)
    names = [column[0] for column in cursor.description]

    result = []
    for raw in cursor.fetchall():
        row = dict(zip(names, raw))
        count = alerts.get(row["cve_id"], 0)
        row["alertas"] = count
        row["alertado"] = count > 0
        result.append(row)
    return result


def filter_scores(rows, categories=None, min_hype=None, min_reality=None) -> list:
    """
    Filtro puro sobre las filas de `load_scores`.

    `categories` vacío o None = sin filtro de categoría. Los mínimos son
    opcionales: 0/None no filtran. Un hype/reality NULL no pasa un mínimo > 0.
    """
    wanted = {category for category in (categories or []) if category}

    def below(value, minimum):
        return minimum is not None and minimum > 0 and (value is None or value < minimum)

    return [
        row for row in rows
        if (not wanted or row.get("category") in wanted)
        and not below(row.get("hype"), min_hype)
        and not below(row.get("reality"), min_reality)
    ]
