"""Three screens from the spec: overview, CVE card, agents. They return full HTML."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import escape

from core.db import get_db
from dashboard.assessment import assessment_html
from dashboard.data import (
    SCATTER_LIMIT,
    VIEW_ALL_LIMIT,
    count_actionables,
    guess_vuln_type,
    hype_components,
    load_actionables,
    load_agent_stats,
    load_daily_averages,
    load_highlights,
    load_products,
    load_latest_score,
    load_mentions,
    load_pocs,
    load_recent_events,
    load_score,
    load_score_history,
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

# Visible "Pay attention to" rows on the home page: fills the right column
# without pushing the fold. The rest shows up through the action filter.
ACTIONABLE_LIMIT = 6

# Default range for the home page and the agents scatter. It must be the same
# in both so they share the cache entry.
DEFAULT_RANGE_DAYS = 30


def parse_dt(valor):
    """Tolerant date: ISO (NVD, Postgres) or RFC 822 (what the RSS publishes)."""
    texto = str(valor or "").strip()
    if not texto or texto in ("—", "None"):
        return None
    try:
        momento = datetime.fromisoformat(texto.replace("Z", "+00:00"))
    except ValueError:
        # Mentions store the date exactly as the feed publishes it
        # ("Fri, 16 Oct 2026 07:00:00 GMT"), not as ISO: without this fallback
        # the whole list came out undated.
        try:
            momento = parsedate_to_datetime(texto)
        except (TypeError, ValueError):
            return None
    # Mix of naive (ISO without a zone) and aware (Postgres): without this they cannot be sorted.
    return momento if momento.tzinfo else momento.replace(tzinfo=timezone.utc)


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


def _sig_badges(item) -> str:
    """Exploitation signals for a CVE as short badges (KEV / PoC / EPSS)."""
    sigs = []
    if item.get("in_kev"):
        fecha = str(item.get("kev_date") or "")[:10]
        sufijo = f" {fecha[5:]}" if len(fecha) == 10 else ""
        sigs.append(f'<span class="s-kev">KEV{sufijo}</span>')
    if item.get('wild_confirmation'):
        sigs.append('<span class="s-kev">Observed exploitation</span>')
    pocs = int(item.get("poc_count") or 0)
    if pocs:
        curated=int(item.get('exploitdb_poc_count') or 0)
        label=f'{curated} PoC' if curated else f'{pocs} candidates'
        description='Public PoC entries from Exploit-DB' if curated else 'Unverified repository candidates'
        sigs.append(f'<span class="s-poc" title="{description}">{label}</span>')
    epss = item.get("epss")
    if epss is not None and float(epss) >= 0.70:
        sigs.append(f'<span class="s-epss">EPSS {float(epss) * 100:.0f}%</span>')
    return "".join(sigs) or '<span class="s-none">—</span>'


def _actionable_rows_html(rows) -> str:
    """"Pay attention to" rows: the signal leads, the date just tags along."""
    out = []
    for item in rows or []:
        sev = str(item.get("cvss_severity") or "—").upper()
        reality = float(item.get("reality") or 0)
        cve = escape(str(item.get("cve_id") or ""))
        out.append(
            "<tr>"
            f'<td><a class="link" href="/cve?cve={cve}">{cve}</a></td>'
            f'<td>{badge(sev, SEVERITY_COLORS.get(sev, "#6B7280"))}</td>'
            f'<td><div class="sig">{_sig_badges(item)}</div></td>'
            f'<td><span class="reality-bar"><i style="width:{min(reality * 10, 100):.0f}%"></i>'
            f'</span><span class="reality-num">{reality:.1f}</span></td>'
            "</tr>"
        )
    if not out:
        return ('<tr><td colspan="4" class="muted">No CVE in range has '
                "exploitation evidence.</td></tr>")
    return "".join(out)


def overview(qp: dict | None = None) -> str:
    qp = qp or {}
    severity = _qp(qp, "severity") or "All severities"
    category = _qp(qp, "category") or "All categories"
    since_s = _qp(qp, "since")
    until_s = _qp(qp, "until")
    show_all = _qp(qp, "all") == "1"
    query = (_qp(qp, "q") or "").strip()
    product = (_qp(qp, "product") or "").strip()
    if product == "All products":
        product = ""
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
    try:
        attention_page=max(0,int(_qp(qp,'attention_page') or 0))
    except ValueError:
        attention_page=0

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
    prod = product or None
    conn = get_db()
    try:
        total = count_scores(conn, since=since, until=until, category=cat, severity=sev,
                             query=query, product=prod)
        products = load_products(conn, since=since, until=until)
        empty_message = 'No CVEs match these publication dates and filters.'
        if not total and not count_scores(conn):
            empty_message = 'No scores are available yet.'
        if show_all:
            page_size = VIEW_ALL_LIMIT
        max_page = max(0, (total - 1) // page_size) if total else 0
        page = min(max(0, page), max_page)
        chunk, scatter_rows, series = [], [], []
        if total:
            chunk = load_scores(
                conn, since=since, until=until, category=cat, severity=sev,
                limit=page_size, offset=page * page_size, order="published", query=query,
                product=prod,
            )
            scatter_rows = load_scores(
                conn, since=since, until=until, category=cat, severity=sev,
                limit=SCATTER_LIMIT, order="hype", query=query, product=prod,
            )
            series = load_daily_averages(
                conn, since=since, until=until, category=cat, severity=sev, product=prod,
                query=query,
            )
            # Inside the block: after close() the connection is useless and the
            # query failed silently, leaving the chart without highlights.
            highlights = load_highlights(
                conn, since=since, until=until, category=cat, severity=sev,
                product=prod, limit=3,
                query=query,
            )
        # Operational queue: all publication dates, other selected filters apply.
        # It goes inside the try because after close() the connection is useless.
        actionable_total = count_actionables(
            conn, since=since, until=until, category=cat, severity=sev,
            query=query, product=prod,
        )
        attention_page=min(attention_page,max(0,(actionable_total-1)//ACTIONABLE_LIMIT))
        actionable_rows_data = load_actionables(
            conn, since=since, until=until, category=cat, severity=sev,
            query=query, product=prod, limit=ACTIONABLE_LIMIT,
            offset=attention_page*ACTIONABLE_LIMIT,
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

    # 760x520 over the card real width: the scatter fills the column
    # height instead of leaving a gap before the timeline.
    scatter_div = (scatter_svg(scatter_rows, width=760, height=640) if scatter_rows
                   else f'<p class="empty">{escape(empty_message)}</p>')
    # At the bottom of the scatter: 760 wide so the dates stay legible when
    # the SVG is scaled to the column.
    timeline_div = timeline_svg(series, width=760, height=78, compact=True)
    actionable_table = _actionable_rows_html(actionable_rows_data)

    return overview_html(
        logo_html=logo(),
        scatter_div=scatter_div,
        timeline_div=timeline_div,
        table_rows="".join(table_rows) or f'<tr><td colspan="5" class="muted">{escape(empty_message)}</td></tr>',
        actionable_rows=actionable_table,
        actionable_total=actionable_total,
        attention_page=attention_page, attention_page_size=ACTIONABLE_LIMIT,
        total=total, page=page, page_size=page_size,
        severity=severity, category=category, since=since_s, until=until_s,
        show_all=show_all, query=query, product=product, products=products,
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
                f'<div class="page">{logo()}<p class="empty">No scores yet. The worker computes them on its next cycle.</p></div>'
            )
        cve_id = row["cve_id"]
        mentions = load_mentions(conn, cve_id)
        poc_repos = load_pocs(conn, cve_id)
        exploit_entries = conn.execute("SELECT source,external_id,url,event_date FROM evidence WHERE cve_id=? AND kind='public-poc' AND active=true ORDER BY source,external_id", (cve_id,)).fetchall()
        series = load_score_history(conn, cve_id)
    finally:
        conn.close()

    sev = str(row.get("cvss_severity") or "—").upper()
    kev = bool(row.get("in_kev"))
    cvss = row.get("cvss_score")
    cvss_label = f"CVSS {cvss if cvss is not None else '—'} ({sev})"
    badges = badge(cvss_label, SEVERITY_COLORS.get(sev, "#6B7280"))
    if kev:
        badges += " " + badge("KEV: KNOWN CATALOG", "#22D3EE")

    labels = {
        "tone": "Headline sample (25%)",
        "media": "Press, 30 days (60%)",
        "cvss": "CVSS",
        "branding": "Grounded branding (15%)",
        "pocs": "PoCs on GitHub",
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

    def _dt(valor):
        return parse_dt(valor)

    def _sello(momento):
        return momento.strftime("%d %b %Y, %H:%M") if momento else ""

    fechas = [d for d in (_dt(m.get("published")) for m in mentions if m.get('kind')=='press') if d]

    # Newly published CVE: a low reality can be missing data, not missing
    # risk. Without this warning, a 2/10 reads as "not that bad".
    publicado = _dt(row.get("published"))
    dias_publicado = (datetime.now(timezone.utc) - publicado).days if publicado else None
    caveat = "Reality is an ordinal threat index, not an exploitation probability or an asset risk score. Hype measures observed attention over 30 days."
    if dias_publicado is not None and dias_publicado <= 30 and not kev:
        caveat += " " + (
            f"Published {dias_publicado} days ago. Exploitation evidence usually "
            "takes weeks to show up: a low reality score can mean there is no "
            "data yet, not that the flaw is mild."
        )

    # Milestones with a real date, in chronological order; undated data goes last.
    hitos = [
        (_dt(row.get("published")), "Published"),
        (_dt(row.get("kev_date")), "Added to the CISA KEV catalog"),
        (min(fechas) if fechas else None, "First press mention"),
        (max(fechas) if fechas else None, "Latest press mention"),
        (_dt(row.get("calculated_at")), "Score calculated"),
    ]
    con_fecha = sorted((h for h in hitos if h[0]), key=lambda h: h[0])
    poc_count = int(row.get("poc_count") or 0)
    sin_fecha = []
    if row.get("brand_name"):
        sin_fecha.append(("Name", str(row["brand_name"])))
    if poc_count:
        sin_fecha.append(("PoCs on GitHub", f"{poc_count} repositories"))

    ev_html = "".join(
        f'<div class="tl-item"><b>{escape(titulo)}</b>'
        f'<div class="muted">{escape(_sello(momento))}</div></div>'
        for momento, titulo in con_fecha
    ) + "".join(
        f'<div class="tl-item"><b>{escape(titulo)}</b>'
        f'<div class="muted">{escape(valor)}</div></div>'
        for titulo, valor in sin_fecha
    )

    def _mencion_html(m, con_titulo=True):
        fuente = m.get("source") or "media"
        kind_label = {'press':'Press', 'advisory':'Technical advisory'}.get(m.get('kind'), 'Source document')
        url = (m.get("url") or "").strip()
        fecha = _sello(_dt(m.get("published"))) or "no date"
        cabeza = (
            f'<a class="link" href="{escape(url)}" target="_blank" rel="noopener">{escape(fuente)}</a>'
            if url else f"<b>{escape(fuente)}</b>"
        )
        titulo = escape(m.get("title") or "") if con_titulo else ""
        detalle = escape(kind_label) + ' · ' + escape(fecha) + (f" · {titulo}" if titulo else "")
        return f'<div class="mention">{cabeza}<div class="muted">{detalle}</div></div>'

    if mentions:
        visibles = "".join(_mencion_html(m) for m in mentions[:5])
        remaining = "".join(_mencion_html(m) for m in mentions[5:])
        men_html = visibles + (
            f'<details class="expand"><summary>See all {len(mentions)} source documents</summary>'
            f'{remaining}</details>' if remaining else ""
        )
    else:
        men_html = '<p class="muted">No source documents yet.</p>'

    if poc_repos:
        rows_html = "".join(
            "<tr>"
            f'<td><a class="link" href="{escape(r.get("url") or "")}" target="_blank" '
            f'rel="noopener">{escape(r.get("repo") or "")}</a></td>'
            f'<td class="num">{int(r.get("stars") or 0):,}</td>'
            f'<td class="num">{int(r.get("forks") or 0):,}</td>'
            f'<td class="muted">{escape(r.get("language") or "—")}</td>'
            f'<td class="muted">{escape(_sello(_dt(r.get("pushed_at"))) or "—")}</td>'
            "</tr>"
            for r in poc_repos
        )
        pocs_html = (
            f'<div class="score hype" style="font-size:40px">{poc_count}</div>'
            '<p class="muted" style="margin-top:0">Public exploit entries / repo candidates</p>'
            f'<details class="expand"><summary>See {len(poc_repos)} repos with metrics</summary>'
            '<table class="mini"><thead><tr><th>Repository</th><th>Stars</th><th>Forks</th>'
            f'<th>Language</th><th>Updated</th></tr></thead><tbody>{rows_html}</tbody></table>'
            "</details>"
        )
    else:
        nota = ("<p class=\"muted\">Source entries and unverified repository candidates are counted separately.</p>"
                if poc_count else "")
        pocs_html = (
            f'<div class="score hype" style="font-size:40px">{poc_count}</div>'
            f'<p class="muted">Public exploit entries / repo candidates</p>{nota}'
        )
    if exploit_entries:
        pocs_html += '<details class="expand"><summary>Public exploit evidence</summary><ul>' + ''.join(
            f'<li><a href="{escape(r["url"] or "")}" target="_blank" rel="noopener">{escape(r["source"])} #{escape(r["external_id"])}</a> {escape(r["event_date"] or "")}</li>'
            for r in exploit_entries) + '</ul></details>'

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
        pocs_html=pocs_html,
        poc_count=poc_count,
        now=now,
        mention_count=len(mentions),
        brand_name=str(row.get("brand_name") or "").strip(),
        timeline=_timeline_html(series),
        caveat=caveat,
        evidence_context=assessment_html(row,mentions),
    )


def _timeline_html(series: list) -> str:
    """Hype/reality series for the CVE. With a single point there is no evolution to see."""
    if not series:
        return ""
    if len(series) == 1:
        punto = series[0]
        return (
            f'<p class="muted">First record: hype {punto["hype"]:.1f} · '
            f'reality {punto["reality"]:.1f} ({escape(str(punto["date"]))}). '
            "The curve appears once the score changes.</p>"
        )
    return timeline_svg(series, width=1100, height=200)


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
    ) or f'<p class="muted">INFO &nbsp; {stats["scores"]} scores · {overhyped} with no evidence of use</p>'
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
