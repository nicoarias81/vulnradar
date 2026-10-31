"""Tres pantallas del mockup: overview, ficha CVE, agentes."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core.db import get_db
from dashboard.data import (
    CATEGORIES,
    daily_averages,
    filter_scores,
    guess_vuln_type,
    hype_components,
    load_agent_stats,
    load_mentions,
    load_scores,
)
from dashboard.theme import (
    CATEGORY_BLURB,
    CATEGORY_COLORS,
    CATEGORY_ES,
    SEVERITY_COLORS,
    header,
    inject,
)

PAGE_SIZE = 6


def _rows():
    conn = get_db()
    try:
        return load_scores(conn)
    finally:
        conn.close()


def _scatter(df: pd.DataFrame, height: int = 420):
    fig = px.scatter(
        df,
        x="reality",
        y="hype",
        color="category",
        color_discrete_map=CATEGORY_COLORS,
        hover_data={"cve_id": True, "cvss_score": True, "hype": ":.2f", "reality": ":.2f"},
        category_orders={"category": list(CATEGORIES)},
    )
    fig.add_shape(
        type="line", x0=0, y0=0, x1=10, y1=10,
        line=dict(dash="dash", color="#64748b", width=1),
    )
    fig.update_traces(marker=dict(size=11, line=dict(width=0)))
    fig.update_layout(
        height=height,
        margin=dict(l=40, r=10, t=10, b=40),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="#0c1424",
        font=dict(color="#c5d0e0", size=12),
        legend=dict(title="", orientation="v", x=1.02, y=1, bgcolor="rgba(0,0,0,0)"),
        xaxis=dict(
            title="REALITY (Observed Impact)",
            range=[-0.2, 10.2],
            gridcolor="#1e2a44",
            zeroline=False,
        ),
        yaxis=dict(
            title="HYPE (Perceived Buzz)",
            range=[-0.2, 10.2],
            gridcolor="#1e2a44",
            zeroline=False,
        ),
    )
    return fig


def _badge(text: str, color: str) -> str:
    return (
        f'<span class="hm-badge" style="background:{color}22;color:{color};'
        f'border:1px solid {color}55">{escape(text)}</span>'
    )


def overview() -> None:
    inject()
    header("Comparing perceived hype against observed impact")
    rows = _rows()
    if not rows:
        st.warning("No hay scores. Corré el seed (`SEED_DEMO=1`) o el pipeline sync → enrich → score.")
        return

    f1, f2, f3, f4 = st.columns(4)
    severities = f1.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=[])
    categories = f2.multiselect("Category", list(CATEGORIES), default=list(CATEGORIES))
    f3.caption("Date range")
    f3.write("All dates")
    f4.caption("Product")
    f4.write("All products")

    filtered = filter_scores(
        rows,
        categories=categories,
        severities=severities or None,
    )
    if not filtered:
        st.info("Ningún CVE pasa los filtros actuales.")
        return

    df = pd.DataFrame(filtered)
    left, right = st.columns([1.15, 1])

    with left:
        st.markdown(
            '<div class="hm-card"><h3>Hype vs Reality</h3>'
            '<p class="hm-muted">Comparing perceived hype (social / media / chatter) against observed impact</p></div>',
            unsafe_allow_html=True,
        )
        st.plotly_chart(_scatter(df), width="stretch")
        legend = " &nbsp; ".join(
            f'<span style="color:{CATEGORY_COLORS[name]}">●</span> <b>{escape(name)}</b> '
            f'<span class="hm-muted">{CATEGORY_BLURB[name]}</span>'
            for name in CATEGORIES
        )
        st.markdown(
            f'<p class="hm-muted">Diagonal separator indicates equilibrium between hype and reality.</p>'
            f"<p>{legend}</p>",
            unsafe_allow_html=True,
        )

    with right:
        total = len(df)
        page = int(st.session_state.get("cve_page", 0))
        max_page = max(0, (total - 1) // PAGE_SIZE)
        page = min(page, max_page)
        chunk = df.iloc[page * PAGE_SIZE : page * PAGE_SIZE + PAGE_SIZE]
        rows_html = []
        for _, item in chunk.iterrows():
            sev = str(item.get("cvss_severity") or "—").upper()
            vtype = guess_vuln_type(item.get("description"))
            pub = str(item.get("published") or "")[:10] or "—"
            score = "—" if pd.isna(item.get("cvss_score")) else f"{float(item.cvss_score):.1f}"
            href = f"?cve={item.cve_id}"
            rows_html.append(
                "<tr>"
                f'<td><a class="hm-link" href="{escape(href)}" target="_self">{escape(item.cve_id)}</a></td>'
                f'<td>{_badge(sev, SEVERITY_COLORS.get(sev, "#94a3b8"))}</td>'
                f'<td style="font-family:IBM Plex Mono,monospace;font-weight:600">{score}</td>'
                f'<td>{_badge(vtype, "#818cf8")}</td>'
                f"<td class='hm-muted'>{escape(pub)}</td>"
                "</tr>"
            )
        st.markdown(
            '<div class="hm-card"><h3>Recent CVEs</h3>'
            '<table class="hm-table"><thead><tr>'
            "<th>CVE ID</th><th>Severity</th><th>Score</th><th>Type</th><th>Published</th>"
            "</tr></thead><tbody>"
            + "".join(rows_html)
            + "</tbody></table></div>",
            unsafe_allow_html=True,
        )
        prev, info, nxt = st.columns([1, 2, 1])
        if prev.button("‹", disabled=page == 0):
            st.session_state["cve_page"] = page - 1
            st.rerun()
        info.caption(f"{page * PAGE_SIZE + 1}–{page * PAGE_SIZE + len(chunk)} of {total}")
        if nxt.button("›", disabled=page >= max_page):
            st.session_state["cve_page"] = page + 1
            st.rerun()

    series = daily_averages(filtered)
    st.markdown(
        '<div class="hm-card"><h3>Score evolution timeline</h3>'
        '<p class="hm-muted">Daily average Hype and Reality scores (by published date)</p></div>',
        unsafe_allow_html=True,
    )
    if series:
        sdf = pd.DataFrame(series)
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=sdf["date"], y=sdf["hype"], name="Hype Score (Perceived)",
            line=dict(color="#fb923c", width=3),
        ))
        fig.add_trace(go.Scatter(
            x=sdf["date"], y=sdf["reality"], name="Reality Score (Observed)",
            line=dict(color="#22d3ee", width=3),
        ))
        fig.update_layout(
            height=260,
            margin=dict(l=40, r=20, t=10, b=40),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#0c1424",
            font=dict(color="#c5d0e0"),
            yaxis=dict(range=[0, 10], gridcolor="#1e2a44", title=""),
            xaxis=dict(gridcolor="#1e2a44"),
            legend=dict(orientation="h", y=-0.25),
        )
        st.plotly_chart(fig, width="stretch")
    else:
        st.caption("Sin fechas de publicación para armar la serie.")


def detail() -> None:
    inject()
    now = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    header("Datos contra el ruido.", extra_html=f"Actualizado: {now}")

    rows = _rows()
    if not rows:
        st.warning("No hay scores para mostrar un CVE.")
        return

    ids = [row["cve_id"] for row in rows]
    requested = st.query_params.get("cve")
    default = requested if requested in ids else ids[0]
    cve_id = st.selectbox("CVE", ids, index=ids.index(default))
    row = next(item for item in rows if item["cve_id"] == cve_id)

    conn = get_db()
    try:
        mentions = load_mentions(conn, cve_id)
    finally:
        conn.close()

    sev = str(row.get("cvss_severity") or "—").upper()
    kev = bool(row.get("in_kev"))
    badges = _badge(f"CVSS {row.get('cvss_score') or '—'} ({sev})", SEVERITY_COLORS.get(sev, "#94a3b8"))
    if kev:
        badges += " " + _badge("KEV: CATÁLOGO CONOCIDO", "#22d3ee")

    st.markdown(
        f"<h1 style='margin:0 0 6px 0;font-family:IBM Plex Mono,monospace'>{escape(cve_id)}</h1>"
        f"<p>{badges}</p>"
        f"<p class='hm-muted'>{escape(row.get('description') or 'Sin descripción.')}</p>",
        unsafe_allow_html=True,
    )

    left, mid, right = st.columns([1.1, 1.1, 1.1])
    components = hype_components(row)
    with left:
        bars = []
        for item in components:
            pct = max(0, min(100, item["value"] * 10))
            bars.append(
                f"<div style='margin:10px 0'><div class='hm-muted'>{escape(item['label'])} "
                f"<b style='float:right;color:#e8eef7'>{int(round(pct))}/100</b></div>"
                f"<div class='hm-bar-wrap'><div class='hm-bar' style='width:{pct}%'></div></div></div>"
            )
        total = int(round(float(row.get("hype") or 0) * 10))
        st.markdown(
            '<div class="hm-card"><h3>Hype components</h3>'
            + "".join(bars)
            + f"<hr style='border-color:#1e2a44'><div>HYPE TOTAL <b class='hm-hype' style='float:right;font-size:1.4rem'>{total}/100</b></div>"
            + "</div>",
            unsafe_allow_html=True,
        )

    with mid:
        cat = row.get("category") or "Quiet"
        st.markdown(
            '<div class="hm-card"><h3>Análisis de hype</h3>'
            '<div style="display:flex;gap:24px;align-items:flex-end">'
            f'<div><div class="hm-muted">HYPE SCORE</div><div class="hm-score hm-hype">{float(row["hype"] or 0):.1f}<small>/10</small></div></div>'
            f'<div><div class="hm-muted">REALITY SCORE</div><div class="hm-score hm-reality">{float(row["reality"] or 0):.1f}<small>/10</small></div></div>'
            "</div>"
            f'<div class="hm-banner"><strong>🔥 {CATEGORY_ES.get(cat, cat)}</strong>'
            f"<p class='hm-muted' style='margin:6px 0 0 0'>{CATEGORY_BLURB.get(cat, '')}</p></div>"
            "</div>",
            unsafe_allow_html=True,
        )

    with right:
        events = [
            ("Publicado", str(row.get("published") or "—")[:16]),
            ("Score calculado", str(row.get("calculated_at") or "—")[:16]),
        ]
        if kev:
            events.append(("En KEV (CISA)", "sí"))
        if row.get("brand_name"):
            events.append(("Nombre", str(row["brand_name"])))
        ev_html = "".join(
            f"<div style='display:flex;gap:10px;margin:8px 0'>"
            f"<span style='color:#22d3ee'>●</span><div><b>{escape(title)}</b>"
            f"<div class='hm-muted'>{escape(str(when))}</div></div></div>"
            for title, when in events
        )
        men_html = "".join(
            f"<div style='margin:8px 0'><b>{escape(m.get('source') or 'media')}</b>"
            f"<div class='hm-muted'>{escape(m.get('title') or m.get('url') or '')}</div></div>"
            for m in mentions[:5]
        ) or "<p class='hm-muted'>Sin menciones RSS todavía.</p>"
        pocs = int(row.get("poc_count") or 0)
        st.markdown(
            f'<div class="hm-card"><h3>Línea de tiempo del evento</h3>{ev_html}</div>'
            f'<div class="hm-card"><h3>Menciones recientes en medios</h3>{men_html}</div>'
            f'<div class="hm-card"><h3>PoCs en GitHub</h3>'
            f'<div class="hm-score hm-hype" style="font-size:2.4rem">{pocs}</div>'
            f'<p class="hm-muted">Repositorios con PoC</p></div>',
            unsafe_allow_html=True,
        )

    st.caption("Fuente: CVE List V5 · CISA KEV · FIRST EPSS · GitHub · RSS")


def agents() -> None:
    inject()
    now = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    header("SOC monitoring · real-time agents", extra_html=f"● LIVE &nbsp; {now}")

    conn = get_db()
    try:
        stats = load_agent_stats(conn)
        rows = load_scores(conn)
    finally:
        conn.close()

    cards = [
        ("Sync Agent", f"{stats['cves']:,}", "RECORDS SYNCED", stats["synced_at"] or "sin watermark"),
        ("Enrichment Agent", f"{stats['enrichments']:,}", "ENTITIES ENRICHED", "KEV · EPSS · RSS · GitHub"),
        ("Scoring Agent", f"{stats['scores']:,}", "SCORED", f"avg hype {stats['avg_hype']} · reality {stats['avg_reality']}"),
        ("Alert Agent", f"{stats['alerts']:,}", "ALERTS TRIGGERED", "dedupe por regla"),
    ]
    cols = st.columns(4)
    for column, (name, value, label, note) in zip(cols, cards):
        column.markdown(
            f'<div class="hm-card"><div class="hm-agent"><div>'
            f'<span class="hm-dot hm-ok"></span><b>{escape(name)}</b>'
            f'<div class="hm-muted">HEALTHY</div></div></div>'
            f'<div class="hm-score" style="font-size:1.8rem;margin-top:10px">{value}</div>'
            f'<div class="hm-muted">{escape(label)}</div>'
            f'<div class="hm-muted">{escape(str(note))}</div></div>',
            unsafe_allow_html=True,
        )

    feed, scatter = st.columns([1.4, 1])
    with feed:
        st.markdown('<div class="hm-card"><h3>Live processing feed</h3></div>', unsafe_allow_html=True)
        recent = sorted(rows, key=lambda r: str(r.get("calculated_at") or ""), reverse=True)[:8]
        body = []
        for item in recent:
            body.append(
                "<tr>"
                f"<td class='hm-muted'>{escape(str(item.get('calculated_at') or '')[:19])}</td>"
                "<td>Scoring Agent</td>"
                f"<td><span class='hm-badge' style='background:#7c3aed33;color:#c4b5fd'>SCORE</span></td>"
                f"<td>{escape(item['cve_id'])} · {escape(item.get('category') or '')} "
                f"{float(item.get('hype') or 0):.1f}/{float(item.get('reality') or 0):.1f}</td>"
                "<td style='color:#22c55e'>SUCCESS</td>"
                "</tr>"
            )
        st.markdown(
            '<table class="hm-table"><thead><tr><th>Time</th><th>Agent</th><th>Event</th>'
            "<th>Entity</th><th>Status</th></tr></thead><tbody>"
            + ("".join(body) or "<tr><td colspan='5'>Sin eventos</td></tr>")
            + "</tbody></table>",
            unsafe_allow_html=True,
        )

    with scatter:
        st.markdown(
            '<div class="hm-card"><h3>Hype vs Reality</h3>'
            '<p class="hm-muted">Signal distribution</p></div>',
            unsafe_allow_html=True,
        )
        if rows:
            st.plotly_chart(_scatter(pd.DataFrame(rows), height=320), width="stretch")

    overhyped = sum(1 for r in rows if r.get("category") == "Overhyped")
    st.markdown(
        f'<div class="hm-card"><h3>System logs</h3>'
        f"<p class='hm-muted'>INFO &nbsp; Sync watermark · {escape(str(stats['synced_at'] or 'demo seed'))}</p>"
        f"<p class='hm-muted'>INFO &nbsp; {stats['scores']} scores vigentes · {overhyped} Overhyped</p>"
        f"<p class='hm-muted'>INFO &nbsp; Alertas enviadas: {stats['alerts']}</p></div>",
        unsafe_allow_html=True,
    )
