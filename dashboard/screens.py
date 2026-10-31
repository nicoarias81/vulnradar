"""Tres pantallas del spec: overview, ficha CVE, agentes. Devuelven HTML completo."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from html import escape

from core.db import get_db
from dashboard.data import (
    SCATTER_LIMIT,
    VIEW_ALL_LIMIT,
    guess_vuln_type,
    hype_components,
    load_agent_stats,
    load_daily_averages,
    load_latest_score,
    load_mentions,
    load_recent_events,
    load_score,
    load_scores,
    count_scores,
)
from dashboard.markup import (
    VTYPE_COLORS,
    agent_card,
    agents_html,
    badge,
    detail_html,
    document,
    hype_bar,
    logo,
    overview_html,
    scatter_svg,
    sparkline_svg,
    timeline_svg,
)
from dashboard.theme import AGENT_COLORS, SEVERITY_COLORS

PAGE_SIZE = 6

# Rango por defecto de la portada y del scatter de agentes. Debe ser el mismo
# en ambos para que compartan la entrada de caché.
DEFAULT_RANGE_DAYS = 30


def _fmt_pub(value) -> str:
    text = str(value or "")[:10]
    if len(text) < 10:
        return text or "—"
    try:
        dt = datetime.strptime(text, "%Y-%m-%d")
        return f"{dt.strftime('%b')} {dt.day}, {dt.year}"
    except ValueError:
        return text


def _qp(qp: dict, key: str, default: str = "") -> str:
    value = qp.get(key, default)
    if isinstance(value, list):
        value = value[0] if value else default
    return str(value if value is not None else default)


def overview(qp: dict | None = None) -> str:
    qp = qp or {}
    severity = _qp(qp, "severity") or "All severities"
    category = _qp(qp, "category") or "All categories"
    since_s = _qp(qp, "since")
    until_s = _qp(qp, "until")
    show_all = _qp(qp, "all") == "1"
    query = (_qp(qp, "q") or "").strip()
    if not since_s and not until_s and not query:
        until_default = datetime.now(timezone.utc).date()
        since_default = until_default - timedelta(days=DEFAULT_RANGE_DAYS)
        since_s = since_default.isoformat()
        until_s = until_default.isoformat()
    try:
        page = int(_qp(qp, "page") or 0)
    except ValueError:
        page = 0
    page_size = PAGE_SIZE

    since = until = None
    if since_s:
        try:
            since = datetime.strptime(since_s, "%Y-%m-%d").date()
        except ValueError:
            since = None
    if until_s:
        try:
            until = datetime.strptime(until_s, "%Y-%m-%d").date()
        except ValueError:
            until = None

    cat = None if category == "All categories" else category
    sev = None if severity == "All severities" else severity
    conn = get_db()
    try:
        total = count_scores(conn, since=since, until=until, category=cat, severity=sev, query=query)
        if not total:
            empty = (
                f'<p class="empty">Sin resultados para «{escape(query)}».</p>'
                if query else
                '<p class="empty">Todavía no hay scores. El worker autónomo los calcula solo.</p>'
            )
            return overview_html(
                logo_html=logo(),
                scatter_div=empty,
                timeline_div="",
                table_rows="",
                total=0, page=0, page_size=page_size,
                severity=severity, category=category, since=since_s, until=until_s,
                show_all=show_all, query=query,
            )
        if show_all:
            page_size = VIEW_ALL_LIMIT
        max_page = max(0, (total - 1) // page_size) if total else 0
        page = min(max(0, page), max_page)
        chunk = load_scores(
            conn, since=since, until=until, category=cat, severity=sev,
            limit=page_size, offset=page * page_size, order="published", query=query,
        )
        scatter_rows = load_scores(
            conn, since=since, until=until, category=cat, severity=sev,
            limit=SCATTER_LIMIT, order="hype",
        )
        series = load_daily_averages(
            conn, since=since, until=until, category=cat, severity=sev,
        )
    finally:
        conn.close()

    table_rows = []
    for item in chunk:
        sev = str(item.get("cvss_severity") or "—").upper()
        vtype = guess_vuln_type(item.get("description"))
        raw_score = item.get("cvss_score")
        score = "—" if raw_score is None else f"{float(raw_score):.1f}"
        href = f"/cve?cve={item['cve_id']}"
        brand = str(item.get("brand_name") or "").strip()
        brand_html = f'<span class="brand-name">{escape(brand)}</span>' if brand else ""
        table_rows.append(
            "<tr>"
            f'<td><a class="link" href="{escape(href)}">{escape(str(item["cve_id"]))}</a>{brand_html}</td>'
            f'<td>{badge(sev, SEVERITY_COLORS.get(sev, "#6B7280"))}</td>'
            f'<td style="font-weight:700;font-variant-numeric:tabular-nums">{score}</td>'
            f'<td>{badge(vtype, VTYPE_COLORS.get(vtype, "#818CF8"))}</td>'
            f'<td class="muted">{escape(_fmt_pub(item.get("published")))}</td>'
            "</tr>"
        )

    scatter_div = scatter_svg(scatter_rows) if scatter_rows else '<p class="empty">Ningún CVE pasa los filtros actuales.</p>'
    timeline_div = timeline_svg(series)

    return overview_html(
        logo_html=logo(),
        scatter_div=scatter_div,
        timeline_div=timeline_div,
        table_rows="".join(table_rows),
        total=total, page=page, page_size=page_size,
        severity=severity, category=category, since=since_s, until=until_s,
        show_all=show_all, query=query,
    )


def detail(qp: dict | None = None) -> str:
    qp = qp or {}
    now = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    requested = _qp(qp, "cve")
    conn = get_db()
    try:
        row = load_score(conn, requested) if requested else load_latest_score(conn)
        if not row:
            return document(
                f'<div class="page">{logo()}<p class="empty">Todavía no hay scores. El worker los calcula solo en el próximo ciclo.</p></div>'
            )
        cve_id = row["cve_id"]
        mentions = load_mentions(conn, cve_id)
    finally:
        conn.close()

    sev = str(row.get("cvss_severity") or "—").upper()
    kev = bool(row.get("in_kev"))
    cvss = row.get("cvss_score")
    cvss_label = f"CVSS {cvss if cvss is not None else '—'} ({sev})"
    badges = badge(cvss_label, SEVERITY_COLORS.get(sev, "#6B7280"))
    if kev:
        badges += " " + badge("KEV: CATÁLOGO CONOCIDO", "#22D3EE")

    labels = {
        "tone": "Titular sensacionalista",
        "media": "Cobertura en medios",
        "cvss": "CVSS",
        "branding": "Branding",
        "pocs": "PoCs en GitHub",
    }
    icons = {"tone": "shield", "media": "clock", "cvss": "bolt", "branding": "tag", "pocs": "git"}
    order = ["tone", "media", "cvss", "branding", "pocs"]
    components_data = sorted(
        hype_components(row),
        key=lambda item: order.index(item["key"]) if item["key"] in order else 99,
    )
    bars = "".join(
        hype_bar(
            labels.get(item["key"], item["label"]),
            int(round(max(0, min(100, item["value"] * 10)))),
            icons.get(item["key"], "clock"),
        )
        for item in components_data
    )

    events = [
        ("Publicado", str(row.get("published") or "—")[:16]),
        ("Score calculado", str(row.get("calculated_at") or "—")[:16]),
    ]
    if kev:
        events.append(("Añadido al catálogo KEV (CISA)", "sí"))
    if row.get("brand_name"):
        events.append(("Nombre", str(row["brand_name"])))
    if int(row.get("poc_count") or 0):
        events.append(("Publicación de PoC en GitHub", str(int(row["poc_count"]))))
    ev_html = "".join(
        f'<div class="tl-item"><b>{escape(title)}</b>'
        f'<div class="muted">{escape(str(when))}</div></div>'
        for title, when in events
    )
    men_html = "".join(
        f'<div style="margin:8px 0"><b>{escape(m.get("source") or "media")}</b>'
        f'<div class="muted">{escape(m.get("title") or m.get("url") or "")}</div></div>'
        for m in mentions[:5]
    ) or '<p class="muted">Sin menciones RSS todavía.</p>'

    return detail_html(
        cve_id=cve_id,
        description=row.get("description") or "",
        badges=badges,
        bars=bars,
        hype=float(row.get("hype") or 0),
        reality=float(row.get("reality") or 0),
        category=row.get("category") or "Quiet",
        events=ev_html,
        mentions=men_html,
        pocs=int(row.get("poc_count") or 0),
        now=now,
        mention_count=len(mentions),
        brand_name=str(row.get("brand_name") or "").strip(),
    )


def _spark_values(events, agent: str, n: int = 16) -> list[float]:
    subset = [item for item in events if str(item.get("agent") or "") == agent]
    if not subset:
        return [0.18] * n
    buckets = [0.0] * n
    for i, item in enumerate(reversed(subset)):
        idx = min(n - 1, i * n // max(len(subset), 1))
        bump = 1.0 if item.get("status") in ("SUCCESS", "INFO", "RUNNING") else 0.45
        buckets[idx] += bump
    peak = max(buckets) or 1.0
    return [0.12 + 0.8 * (value / peak) for value in buckets]


def agents(_qp: dict | None = None) -> str:
    today = datetime.now(timezone.utc).date()
    conn = get_db()
    try:
        stats = load_agent_stats(conn)
        overhyped = conn.execute(
            "SELECT COUNT(*) FROM scores WHERE category = 'Overhyped'"
        ).fetchone()[0]
        events = load_recent_events(conn, 80)
        rows = load_scores(
            conn,
            since=today - timedelta(days=DEFAULT_RANGE_DAYS),
            until=today,
            limit=SCATTER_LIMIT,
            order="hype",
        )
    finally:
        conn.close()
    now = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    last = stats.get("agents") or {}
    specs = [
        ("sync", "Sync Agent", (f"{stats['cves']:,}", "RECORDS SYNCED"), (str(stats["synced_at"] or "—")[:16] or "—", "LAST SYNC")),
        ("enrich", "Enrichment Agent", (f"{stats['enrichments']:,}", "ENTITIES ENRICHED"), ("KEV · EPSS", "SOURCES")),
        ("score", "Scoring Agent", (f"{stats['scores']:,}", "SCORED"), (f"{stats['avg_hype']}/{stats['avg_reality']}", "AVG HYPE / REALITY")),
        ("alert", "Alert Agent", (f"{stats['alerts']:,}", "ALERTS TRIGGERED"), (str(overhyped), "OVERHYPED")),
    ]
    cards = "".join(
        agent_card(
            key, name, (last.get(key) or {}).get("status") or "PENDING", a, b,
            spark=sparkline_svg(_spark_values(events, key), AGENT_COLORS.get(key, "#FF6B00")),
        )
        for key, name, a, b in specs
    )
    feed = []
    for item in events[:12]:
        color = "#22C55E" if item["status"] == "SUCCESS" else (
            "#EAB308" if item["status"] == "RUNNING" else "#EF4444"
        )
        feed.append(
            "<tr>"
            f'<td class="muted">{escape(str(item.get("ts") or "")[:19])}</td>'
            f"<td>{escape(str(item.get('agent') or ''))}</td>"
            f"<td>{badge(str(item.get('event_type') or ''), AGENT_COLORS.get(str(item.get('agent') or ''), '#A78BFA'))}</td>"
            f'<td class="muted">{escape(str(item.get("details") or "")[:80])}</td>'
            f'<td style="color:{color}">{escape(str(item.get("status") or ""))}</td>'
            "</tr>"
        )
    scatter_div = scatter_svg(rows, width=480, height=280, mode="split") if rows else ""
    logs = events[:6] or []
    log_html = "".join(
        _log_row(item) for item in logs
    ) or f'<p class="muted">INFO &nbsp; {stats["scores"]} scores · {overhyped} Overhyped</p>'
    return agents_html(
        now=now, cards=cards, feed_rows="".join(feed),
        scatter_div=scatter_div, logs=log_html,
    )


def _log_row(item: dict) -> str:
    status = str(item.get("status") or "INFO")
    level = "ERROR" if status == "ERROR" else ("WARN" if status in ("RUNNING", "TRIGGERED") else "INFO")
    ts = str(item.get("ts") or "")[11:19] or "—"
    agent = str(item.get("agent") or "System")
    details = str(item.get("details") or "")[:140]
    return (
        f'<div class="log-row"><span>{escape(ts)}</span><span>UTC</span>'
        f'<span class="lvl-{level}">{level}</span>'
        f"<span>{escape(agent)}</span><span>{escape(details)}</span></div>"
    )
