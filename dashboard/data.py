"""
Score loading and filtering for the dashboard.

Pure module (psycopg + stdlib, no Streamlit or pandas): the UI is tested with
pytest without booting the Streamlit runtime. The home queries cap in
SQL (COUNT, LIMIT/OFFSET, GROUP BY): tens of thousands of rows are never materialized.
"""
import re
import json
from core.reference_cases import match_case

from core.db import has_table

CATEGORIES = ("Overhyped", "Earned the hype", "Sleeper", "Quiet", "Unknown", "Watch")

SCORE_COLUMNS = (
    "cve_id", "hype", "reality", "category", "calculated_at",
    "description", "cvss_score", "cvss_severity", "published",
    "tone_score", "media_count", "in_kev", "epss", "poc_count",
    "branding", "brand_name", "alertas", "alertado",
)

SCATTER_LIMIT = 400
VIEW_ALL_LIMIT = 100

# Publication day (ISO) or, if missing, the score day. TEXT + TIMESTAMPTZ.
# The date that rules is the CVE publication date. Falling back to the
# calculation date pushed undated CVEs into "recent" (Exploit-DB/GHSA stubs)
# because their day became today; without a date, a CVE is not recent.
_DAY_EXPR = "left(c.published, 10)"

SELECT_SCORES_BASE = """
    SELECT s.cve_id, s.hype, s.reality, s.category, s.calculated_at,
           c.description, c.cvss_score, c.cvss_severity, c.cvss_vector, c.cvss_source, c.published,
           e.tone_score, e.media_count, e.in_kev, e.epss, e.poc_count,
           e.branding, e.brand_name, e.kev_date, e.wild_confirmation, e.exploitdb_poc_count, e.github_poc_count,
           e.epss_date, e.validated_poc_count, s.exploitation_state, s.completeness, s.algorithm_version, ev.input_snapshot
    FROM scores s
    JOIN cves c ON c.cve_id = s.cve_id
    LEFT JOIN enrichments e ON e.cve_id = s.cve_id
    LEFT JOIN score_evaluations ev ON ev.cve_id=s.cve_id AND ev.input_hash=s.input_hash
"""


def _filters(since=None, until=None, category=None, severity=None, query=None, product=None):
    clauses: list[str] = []
    params: list = []
    if since:
        clauses.append(f"{_DAY_EXPR} >= ?")
        params.append(str(since)[:10])
    if until:
        clauses.append(f"{_DAY_EXPR} <= ?")
        params.append(str(until)[:10])
    if category and category not in ("All categories",):
        clauses.append("s.category = ?")
        params.append(category)
    if severity and severity not in ("All severities",):
        clauses.append("upper(c.cvss_severity) = ?")
        params.append(str(severity).upper())
    if product and product not in ("All products",):
        # ILIKE: the selector lets you type the name by hand, not just pick it.
        clauses.append("c.product ILIKE ?")
        params.append(str(product))
    if query:
        text = str(query).strip()
        reference = match_case(text)
        if reference:
            clauses.append('s.cve_id = ANY(?)')
            params.append(reference['cves'])
            return clauses, params
        if text:
            like = f"%{text}%"
            # Each path uses its own index (trigram for id/nickname/product, GIN
            # full-text for description). A loose OR forced a seq scan: 20 s.
            clauses.append("""s.cve_id IN (
            SELECT cve_id FROM cves WHERE cve_id ILIKE ?
            UNION
            SELECT cve_id FROM enrichments WHERE brand_name ILIKE ?
            UNION
            SELECT cve_id FROM cves WHERE product ILIKE ?
            UNION
            SELECT cve_id FROM cves
            WHERE to_tsvector('english', coalesce(description, ''))
                  @@ plainto_tsquery('english', ?)
        )""")
            params.extend([like, like, like, text])
    return clauses, params


CVE_SHAPE = re.compile(r"^\d{4}-\d{4,}$")


def find_cve_id(conn, query: str):
    """Exact CVE id for a text: accepts `CVE-2021-44228`, `2021-44228` or the
    nickname (`Log4Shell`). If the text leaves a single candidate by description,
    it returns that one too. None when there is no unique match."""
    text = (query or "").strip()
    if not text:
        return None
    reference = match_case(text)
    if reference:
        if len(reference['cves'])!=1:
            return None
        row=conn.execute('SELECT cve_id FROM cves WHERE cve_id=?',(reference['cves'][0],)).fetchone()
        return row[0] if row else None
    upper = text.upper()
    candidates = [upper]
    if CVE_SHAPE.match(upper):
        candidates.append(f"CVE-{upper}")
    for cand in candidates:
        row = conn.execute("SELECT cve_id FROM cves WHERE upper(cve_id) = ? LIMIT 1", (cand,)).fetchone()
        if row:
            return row[0]
    row = conn.execute(
        "SELECT cve_id FROM enrichments WHERE upper(btrim(brand_name)) = ? LIMIT 1", (upper,)
    ).fetchone()
    if row:
        return row[0]
    rows = conn.execute(
        "SELECT cve_id FROM scores s JOIN cves c ON c.cve_id = s.cve_id "
        "WHERE to_tsvector('english', coalesce(c.description, '')) "
        "      @@ plainto_tsquery('english', ?) LIMIT 2",
        (text,),
    ).fetchall()
    return rows[0][0] if len(rows) == 1 else None


def _where(clauses: list[str]) -> str:
    if not clauses:
        return ""
    return "    WHERE " + " AND ".join(clauses) + "\n"


def _order_sql(order: str) -> str:
    if order in ("published", "recent", "date"):
        # Newest first by real publication date. NULLS LAST and the
        # cve_id tiebreak: without that, every row calculated in the same
        # cycle ties and alphabetical order pulls 2023 CVEs to the top.
        return "    ORDER BY c.published DESC NULLS LAST, s.cve_id\n"
    if order == "hype":
        return (
            "    ORDER BY (e.brand_name IS NOT NULL AND btrim(e.brand_name) <> '') DESC,"
            " s.hype DESC NULLS LAST, s.cve_id\n"
        )
    return "    ORDER BY s.calculated_at DESC NULLS LAST, s.cve_id\n"


def _attach_alerts(conn, rows: list) -> list:
    if not rows:
        return rows
    if not has_table(conn, "alerts_sent"):
        for row in rows:
            row["alertas"] = 0
            row["alertado"] = False
        return rows
    alerts = load_alert_counts(conn, [row["cve_id"] for row in rows])
    for row in rows:
        count = alerts.get(row["cve_id"], 0)
        row["alertas"] = count
        row["alertado"] = count > 0
    return rows


def _fetch_dicts(cursor) -> list:
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, raw)) for raw in cursor.fetchall()]


def load_alert_counts(conn, cve_ids=None) -> dict:
    """Number of alerts sent per CVE. Without the table, no CVE is alerted."""
    if not has_table(conn, "alerts_sent"):
        return {}
    if cve_ids is not None:
        if not cve_ids:
            return {}
        placeholders = ", ".join("?" for _ in cve_ids)
        rows = conn.execute(
            f"SELECT cve_id, COUNT(*) FROM alerts_sent WHERE cve_id IN ({placeholders}) GROUP BY cve_id",
            tuple(cve_ids),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT cve_id, COUNT(*) FROM alerts_sent GROUP BY cve_id"
        ).fetchall()
    return {row[0]: int(row[1]) for row in rows}


def count_scores(conn, since=None, until=None, category=None, severity=None, query=None,
                 product=None) -> int:
    clauses, params = _filters(since, until, category, severity, query, product)
    sql = (
        "SELECT COUNT(*) FROM scores s "
        "JOIN cves c ON c.cve_id = s.cve_id "
        "LEFT JOIN enrichments e ON e.cve_id = s.cve_id\n"
        + _where(clauses)
    )
    row = conn.execute(sql, params).fetchone()
    return int(row[0] if row and row[0] is not None else 0)


# "Actionable" criterion: exploitation evidence, not severity. A CVE gets in
# if a trusted source observed exploitation, if fresh EPSS probability is >=70%, or if
# a public PoC already exists. CVSS does not take part: 9.8 without exploitation is not actionable.
ACTIONABLE_WHERE = (
    "(COALESCE(e.in_kev, 0) <> 0 OR COALESCE(e.wild_confirmation,0) <> 0 "
    "OR (e.epss >= 0.70 AND left(e.epss_date,10) >= to_char(CURRENT_TIMESTAMP-INTERVAL '7 days','YYYY-MM-DD') AND left(e.epss_date,10)<=to_char(CURRENT_TIMESTAMP,'YYYY-MM-DD')) "
    "OR COALESCE(e.exploitdb_poc_count,0)>0 OR COALESCE(e.validated_poc_count,0)>0)"
)
# Order by evidence, not by date: KEV first, then exploit
# probability and PoC. `reality` breaks ties within each tier.
ACTIONABLE_ORDER = (
    "    ORDER BY (COALESCE(e.in_kev, 0) <> 0) DESC,\n"
    "             (COALESCE(e.wild_confirmation,0) <> 0) DESC,\n"
    "             COALESCE(e.epss, 0) DESC,\n"
    "             COALESCE(e.poc_count, 0) DESC,\n"
    "             s.reality DESC, s.cve_id\n"
)


def load_actionables(conn, since=None, until=None, category=None, severity=None,
                     query=None, product=None, limit: int = 6, offset: int = 0) -> list:
    """Page of exploitation evidence across publication dates, with other filters."""
    # Exploitation queue is driven by evidence; publication age never hides it.
    clauses, params = _filters(None, None, category, severity, query, product)
    clauses.append(ACTIONABLE_WHERE)
    sql = SELECT_SCORES_BASE + _where(clauses) + ACTIONABLE_ORDER + "    LIMIT ? OFFSET ?\n"
    cursor = conn.execute(sql, list(params) + [max(0,int(limit)), max(0,int(offset))])
    return _attach_alerts(conn, _fetch_dicts(cursor))


def count_actionables(conn, since=None, until=None, category=None, severity=None,
                      query=None, product=None) -> int:
    """How many CVEs in the range meet the actionable criterion."""
    clauses, params = _filters(None, None, category, severity, query, product)
    clauses.append(ACTIONABLE_WHERE)
    sql = (
        "SELECT COUNT(*) FROM scores s "
        "JOIN cves c ON c.cve_id = s.cve_id "
        "LEFT JOIN enrichments e ON e.cve_id = s.cve_id\n"
        + _where(clauses)
    )
    row = conn.execute(sql, params).fetchone()
    return int(row[0] if row and row[0] is not None else 0)


def load_products(conn, since=None, until=None, limit: int = 40) -> list:
    """Products with the most CVEs in the range: initial selector options.

    Alphabetical order: the dropdown is for searching by name, not for
    showing a ranking by volume.
    """
    clauses, params = _filters(since, until)
    clauses = clauses + ["c.product IS NOT NULL", "btrim(c.product) <> ''"]
    sql = (
        "SELECT c.product AS product, COUNT(*) AS n "
        "FROM scores s JOIN cves c ON c.cve_id = s.cve_id\n"
        + _where(clauses)
        + "    GROUP BY c.product ORDER BY lower(c.product), c.product\n"
        "    LIMIT ?\n"
    )
    return _fetch_dicts(conn.execute(sql, list(params) + [int(limit)]))


def search_products(conn, query: str = "", limit: int = 20) -> list:
    """Products that contain `query`, ordered alphabetically.

    Feeds the filter autocomplete: with 60k distinct products you cannot
    send the whole list to the browser, so the search happens on the server.
    """
    clauses = ["c.product IS NOT NULL", "btrim(c.product) <> ''"]
    params: list = []
    text = (query or "").strip()
    if text:
        clauses.append("c.product ILIKE ?")
        params.append(f"%{text}%")
    sql = (
        "SELECT c.product AS product, COUNT(*) AS n FROM cves c"
        + _where(clauses)
        + "    GROUP BY c.product ORDER BY lower(c.product), c.product"
        + "    LIMIT ?"
    )
    params.append(int(limit))
    return _fetch_dicts(conn.execute(sql, params))


def load_scores(
    conn,
    since=None,
    until=None,
    category=None,
    severity=None,
    limit=None,
    offset=0,
    order="calculated_at",
    query=None,
    product=None,
) -> list:
    """
    Current scores with their CVE and enrichment.

    Empty DB -> empty list. `limit`/`offset` cap in SQL (home: table and scatter).
    `query` filters by CVE id, nickname (brand_name), product or description.
    """
    clauses, params = _filters(since, until, category, severity, query, product)
    sql = SELECT_SCORES_BASE + _where(clauses) + _order_sql(order)
    if limit is not None:
        sql += "    LIMIT ? OFFSET ?\n"
        params = list(params) + [int(limit), int(offset or 0)]
    cursor = conn.execute(sql, params)
    return _attach_alerts(conn, _fetch_dicts(cursor))


def load_score(conn, cve_id: str):
    """A single CVE card. None if there is no score."""
    sql = SELECT_SCORES_BASE + "    WHERE s.cve_id = ?\n"
    cursor = conn.execute(sql, (cve_id,))
    rows = _attach_alerts(conn, _fetch_dicts(cursor))
    return rows[0] if rows else None


def load_score_history(conn, cve_id: str, limit: int = 60) -> list:
    """Score evolution for a CVE, oldest to newest.

    `scores` keeps only the current row (UNIQUE(cve_id)), so the series comes from
    score_history: one row per real change in hype or reality.
    """
    sql = (
        "SELECT captured_at, hype, reality, category FROM score_history "
        "WHERE cve_id = ? ORDER BY captured_at DESC LIMIT ?"
    )
    rows = conn.execute(sql, (cve_id, limit)).fetchall()
    series = []
    for row in reversed(rows):
        hype = row["hype"]
        reality = row["reality"]
        series.append({
            # Date and time: several snapshots land on the same day and would overwrite each other.
            "date": str(row["captured_at"])[:16].replace("T", " "),
            "hype": round(float(hype), 2) if hype is not None else None,
            "reality": round(float(reality), 2) if reality is not None else None,
            "category": row["category"],
        })
    return series


def load_latest_score(conn):
    rows = load_scores(conn, limit=1, order="calculated_at")
    return rows[0] if rows else None


def load_daily_averages(conn, since=None, until=None, category=None, severity=None,
                        product=None, query=None) -> list:
    """Average hype/reality per day, aggregated in SQL."""
    clauses, params = _filters(since, until, category, severity, query, product)
    sql = (
        f"SELECT {_DAY_EXPR} AS date, "
        "AVG(s.hype) AS hype, AVG(s.reality) AS reality, COUNT(*) AS n "
        "FROM scores s "
        "JOIN cves c ON c.cve_id = s.cve_id "
        "LEFT JOIN enrichments e ON e.cve_id = s.cve_id\n"
        + _where(clauses)
        + f"    GROUP BY {_DAY_EXPR}\n"
        + f"    ORDER BY {_DAY_EXPR}\n"
    )
    series = []
    for row in conn.execute(sql, params).fetchall():
        hype = row["hype"]
        reality = row["reality"]
        series.append({
            "date": str(row["date"])[:10],
            "hype": round(float(hype), 2) if hype is not None else None,
            "reality": round(float(reality), 2) if reality is not None else None,
            "n": int(row["n"]),
        })
    return _attach_top_cves(conn, series, clauses, params)


def load_highlights(conn, since=None, until=None, category=None, severity=None,
                    product=None, limit: int = 3, query=None) -> list:
    """The noisiest CVEs of the period: the chart labels and links them.

    Top per day is not enough: the daily average is always low and would
    highlight irrelevant CVEs. This goes by absolute hype.
    """
    clauses, params = _filters(since, until, category, severity, query, product)
    sql = (
        f"SELECT s.cve_id, s.hype, s.reality, {_DAY_EXPR} AS day, e.brand_name "
        "FROM scores s JOIN cves c ON c.cve_id = s.cve_id "
        "LEFT JOIN enrichments e ON e.cve_id = s.cve_id"
        + _where(clauses)
        + "\nORDER BY s.hype DESC NULLS LAST, s.calculated_at DESC LIMIT ?"
    )
    try:
        rows = conn.execute(sql, list(params) + [max(1, int(limit))]).fetchall()
    except Exception:
        return []  # without highlights the chart still works
    return [
        {
            "cve_id": f["cve_id"],
            "hype": round(float(f["hype"]), 2) if f["hype"] is not None else 0.0,
            "reality": round(float(f["reality"]), 2) if f["reality"] is not None else 0.0,
            "date": str(f["day"])[:10],
            "brand_name": f["brand_name"] or "",
        }
        for f in rows
    ]


def _attach_top_cves(conn, series, clauses, params) -> list:
    if not series:
        return series
    sql = (
        f"SELECT DISTINCT ON (day) day, cve_id, hype, reality, brand_name FROM ("
        f"  SELECT {_DAY_EXPR} AS day, s.cve_id, s.hype, s.reality, e.brand_name "
        "   FROM scores s JOIN cves c ON c.cve_id = s.cve_id "
        "   LEFT JOIN enrichments e ON e.cve_id = s.cve_id"
        + _where(clauses)
        + ") t ORDER BY day, hype DESC"
    )
    try:
        rows = conn.execute(sql, params).fetchall()
    except Exception:
        return series  # without the top the chart still works
    por_dia = {
        str(f["day"])[:10]: {
            "cve_id": f["cve_id"],
            "hype": round(float(f["hype"]), 2) if f["hype"] is not None else None,
            "brand_name": f["brand_name"] or "",
        }
        for f in rows
    }
    for item in series:
        item["top_cve"] = por_dia.get(item["date"])
    return series


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
    Pure filter over the `load_scores` rows.

    Empty or None `categories` = no category filter. The minimums are
    optional: 0/None do not filter. A NULL hype/reality does not pass a minimum > 0.
    `severities` compares cvss_severity uppercased. Dates use `published`
    (if missing, `calculated_at`); without a date the row fails an active range.
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
    """Average hype/reality per publication day (or calculated_at)."""
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


def load_pocs(conn, cve_id: str, limit: int = 40) -> list:
    """PoC repos with metrics for the CVE card."""
    if not has_table(conn, "pocs"):
        return []
    cursor = conn.execute(
        """
        SELECT repo, url, stars, forks, language, pushed_at, created_at
        FROM pocs
        WHERE cve_id = ?
        ORDER BY stars DESC, repo
        LIMIT ?
        """,
        (cve_id, max(1, int(limit))),
    )
    return _fetch_dicts(cursor)


def load_mentions(conn, cve_id: str) -> list:
    if not has_table(conn, "media_mentions"):
        return []
    cursor = conn.execute(
        """
        SELECT url, title, source, published, kind, domain, story_key
        FROM media_mentions
        WHERE cve_id = ?
        ORDER BY published DESC, created_at DESC
        """,
        (cve_id,),
    )
    return _fetch_dicts(cursor)


def load_agent_stats(conn) -> dict:
    """Real numbers from the DB for the agents panel (no live telemetry)."""
    def count(sql, default=0):
        try:
            row = conn.execute(sql).fetchone()
            return int(row[0] if row and row[0] is not None else default)
        except Exception:
            return default

    n_cves = count("SELECT COUNT(*) FROM cves")
    n_enrich = count("SELECT COUNT(*) FROM enrichments")
    n_scores = count("SELECT COUNT(*) FROM scores")
    n_alerts = count("SELECT COUNT(*) FROM alerts_sent") if has_table(conn, "alerts_sent") else 0
    avg_row = conn.execute(
        "SELECT AVG(hype) AS avg_hype, AVG(reality) AS avg_reality FROM scores"
    ).fetchone()
    avg_hype = round(float(avg_row[0] or 0), 1)
    avg_reality = round(float(avg_row[1] or 0), 1)

    sync_at = None
    if has_table(conn, "sync_state"):
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
    if not has_table(conn, "agent_events"):
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
    return _fetch_dicts(cursor)


def load_last_agent_status(conn) -> dict:
    """Last event per agent (sync/enrich/score/alert)."""
    if not has_table(conn, "agent_events"):
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
    """0-10 bars aligned with the hype formula (it does not invent social/Google data)."""
    from core.normalizer import media_score
    snapshot = json.loads(row.get('input_snapshot') or '{}').get('signals', {})
    media = snapshot.get('media_score', media_score(int(row.get("media_count") or 0)))
    return [
        {"key": "media", "label": "Media, 30 days (60%)", "value": media},
        {"key": "tone", "label": "Headline sample (25%)", "value": float(snapshot.get('tone_score',row.get("tone_score")) or 0)},
        {"key": "branding", "label": "Grounded branding (15%)", "value": 10.0 if snapshot.get('branding',row.get("branding")) else 0.0},
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
