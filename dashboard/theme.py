"""Look & feel: tokens y componentes del paquete humo-vs-miedo-ui-specs."""

CATEGORY_COLORS = {
    "Overhyped": "#EF4444",
    "Sleeper": "#EAB308",
    "Earned the hype": "#22C55E",
    "Quiet": "#6B7280",
}

CATEGORY_BLURB = {
    "Overhyped": "High hype, low impact",
    "Sleeper": "Moderate hype, emerging impact",
    "Earned the hype": "High hype, high impact",
    "Quiet": "Low hype, low impact",
}

CATEGORY_ES = {
    "Overhyped": "SOBREVALORADO",
    "Earned the hype": "GANÓ EL HYPE",
    "Sleeper": "SLEEPER",
    "Quiet": "SILENCIOSO",
}

CATEGORY_DETAIL = {
    "Overhyped": "La percepción pública excede la realidad técnica.",
    "Earned the hype": "El impacto observado respalda el ruido mediático.",
    "Sleeper": "El impacto crece más rápido que la atención pública.",
    "Quiet": "Poco ruido y poco impacto observado.",
}

SEVERITY_COLORS = {
    "CRITICAL": "#EF4444",
    "HIGH": "#FF6B00",
    "MEDIUM": "#EAB308",
    "LOW": "#6B7280",
}

AGENT_COLORS = {
    "sync": "#FF6B00",
    "enrich": "#22D3EE",
    "score": "#A78BFA",
    "alert": "#FB923C",
}

FLAME_SVG = """
<svg class="hm-flame-svg" viewBox="0 0 24 24" aria-hidden="true">
  <path fill="#FF6B00" d="M12 1.8c.2 3.4-2.2 5.4-2.4 8.4 0 1.6 1.1 3 2.4 3s2.4-1.4 2.4-3c0-2.2 1.8-3.6 2.8-5.6 2.4 2.8 3.6 6 3.6 8.8 0 5-3.8 8.8-8.8 8.8S3.2 18.4 3.2 13.4C3.2 8.8 7 4.4 12 1.8z"/>
  <path fill="#FFB347" d="M12 13.2c.2 1.4-.8 2.3-1.4 3.6.8 1.1 1.4 1.7 1.4 1.7s1.4-1 2-2.5c-.6-1.6-1.6-2.3-2-2.8z"/>
</svg>
"""

FLAME_SM = (
    '<svg class="hm-ico" viewBox="0 0 24 24" aria-hidden="true">'
    '<path fill="#FF6B00" d="M12 1.8c.2 3.4-2.2 5.4-2.4 8.4 0 1.6 1.1 3 2.4 3s2.4-1.4 2.4-3c0-2.2 1.8-3.6 2.8-5.6 2.4 2.8 3.6 6 3.6 8.8 0 5-3.8 8.8-8.8 8.8S3.2 18.4 3.2 13.4C3.2 8.8 7 4.4 12 1.8z"/>'
    "</svg>"
)

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

:root {
  --bg: #0F172A;
  --card: #1E293B;
  --elevated: #334155;
  --text: #F8FAFC;
  --text-muted: #94A3B8;
  --hype: #FF6B00;
  --reality: #22D3EE;
  --overhyped: #EF4444;
  --earned: #22C55E;
  --sleeper: #EAB308;
  --quiet: #6B7280;
  --border: #334155;
}

html, body, [data-testid="stAppViewContainer"], .stApp,
[data-testid="stAppViewContainer"] > .main {
  background: var(--bg) !important;
  color: var(--text) !important;
  font-family: Inter, system-ui, -apple-system, sans-serif !important;
}
[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stToolbar"], #MainMenu, footer, [data-testid="stDecoration"],
.stAppDeployButton, [data-testid="stStatusWidget"] {
  visibility: hidden; height: 0;
}
.block-container {
  padding-top: 0.45rem !important;
  padding-bottom: 1.25rem !important;
  padding-left: 1.25rem !important;
  padding-right: 1.25rem !important;
  max-width: 1360px !important;
}
[data-testid="stSidebar"] { background: var(--bg); }
[data-testid="stSidebarNavLink"] { font-family: Inter, sans-serif; }

.hm-top {
  display: flex; align-items: center; justify-content: space-between;
  gap: 16px; min-height: 64px; padding: 8px 0 12px 0; flex-wrap: wrap;
}
.hm-brand { display: flex; align-items: center; gap: 10px; }
.hm-flame-svg { width: 36px; height: 36px; display: block; flex-shrink: 0; }
.hm-ico { width: 16px; height: 16px; display: inline-block; vertical-align: -3px; margin-right: 6px; }
.hm-title {
  font-size: 1.5rem; font-weight: 700; letter-spacing: .01em;
  margin: 0; color: var(--text); line-height: 1.15;
}
.hm-title .hm-humo { color: var(--hype); }
.hm-sub { color: var(--text-muted); font-size: .8rem; margin: 2px 0 0 0; }
.hm-live { color: var(--text-muted); font-size: .78rem; letter-spacing: .06em; text-transform: uppercase; }
.hm-live b { color: var(--earned); font-weight: 600; }

.hm-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px 18px;
  margin-bottom: 16px;
}
.hm-card h3, .hm-h3 {
  font-size: .72rem; letter-spacing: .1em; text-transform: uppercase;
  color: var(--text-muted); margin: 0 0 6px 0; font-weight: 600;
}
[data-testid="stHeaderActionElements"] { display: none !important; }
.hm-h3.hm-accent { color: var(--hype); }
.hm-muted { color: var(--text-muted); font-size: .8rem; }
.hm-filter-label {
  color: var(--text-muted); font-size: .7rem; letter-spacing: .08em;
  text-transform: uppercase; margin: 0 0 4px 0; font-weight: 600;
}

.hm-badge {
  display: inline-block; padding: 3px 10px; border-radius: 999px;
  font-size: .72rem; font-weight: 600; letter-spacing: .04em;
}
.hm-cat-overhyped { background: rgba(239,68,68,.2); color: #fff; }
.hm-cat-earned { background: rgba(34,197,94,.2); color: #4ADE80; }
.hm-cat-sleeper { background: rgba(234,179,8,.2); color: #FACC15; }
.hm-cat-quiet { background: rgba(107,114,128,.25); color: #E5E7EB; }

.hm-link { color: #60A5FA; text-decoration: none; font-weight: 600; font-variant-numeric: tabular-nums; }
.hm-link:hover { text-decoration: underline; }

.hm-table { width: 100%; border-collapse: collapse; font-size: .86rem; }
.hm-table th {
  text-align: left; color: var(--text-muted); font-size: .7rem; letter-spacing: .08em;
  text-transform: uppercase; padding: 8px 6px; border-bottom: 1px solid var(--border);
  font-weight: 600;
}
.hm-table td {
  padding: 10px 6px; border-bottom: 1px solid var(--border); vertical-align: middle;
  color: var(--text);
}
.hm-table tr:hover td { background: var(--elevated); }

.hm-bar-wrap { background: var(--elevated); border-radius: 6px; height: 8px; width: 100%; }
.hm-bar { height: 8px; border-radius: 6px; background: linear-gradient(90deg, #FF6B00, #FB923C); }

.hm-hype-row {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 10px 12px;
  margin: 8px 0;
}
.hm-hype-row .hm-muted { text-transform: uppercase; letter-spacing: .06em; font-size: .68rem; }
.hm-hype-total {
  display: flex; justify-content: space-between; align-items: center;
  background: rgba(255,107,0,.08); border: 1px solid rgba(255,107,0,.35);
  border-radius: 10px; padding: 12px 14px; margin-top: 12px;
  color: var(--hype); font-weight: 700; letter-spacing: .08em;
}
.hm-hype-total b { font-size: 1.35rem; font-variant-numeric: tabular-nums; }

.hm-score {
  font-size: 3.6rem; font-weight: 700; line-height: 1;
  font-variant-numeric: tabular-nums;
}
.hm-score small { font-size: 1rem; color: var(--text-muted); font-weight: 600; }
.hm-hype { color: var(--hype); }
.hm-reality { color: var(--reality); }
.hm-score-row {
  display: flex; gap: 0; align-items: flex-end; justify-content: space-around;
  margin: 18px 0 20px 0;
}
.hm-score-col { text-align: left; padding: 0 12px; flex: 1; }
.hm-score-col + .hm-score-col { border-left: 1px solid var(--border); }

.hm-banner {
  border: 1px solid rgba(255,107,0,.45); background: rgba(255,107,0,.08);
  border-radius: 12px; padding: 14px 16px; margin-top: 8px;
}
.hm-banner strong { color: var(--hype); letter-spacing: .06em; }

.hm-cve-head {
  display: flex; justify-content: space-between; align-items: flex-start;
  gap: 16px; flex-wrap: wrap; margin: 4px 0 14px 0;
}
.hm-cve-head h1 {
  margin: 0 0 6px 0; font-size: 1.85rem; font-weight: 700;
  font-variant-numeric: tabular-nums; color: var(--text);
}
.hm-cve-head .hm-badges { display: flex; gap: 8px; flex-wrap: wrap; padding-top: 6px; }

.hm-tl { border-left: 2px solid var(--reality); margin: 8px 0 4px 7px; padding-left: 16px; }
.hm-tl-item { position: relative; margin: 0 0 14px 0; }
.hm-tl-item::before {
  content: ""; position: absolute; left: -21px; top: 5px;
  width: 10px; height: 10px; border-radius: 50%; background: var(--reality);
  box-shadow: 0 0 0 3px rgba(34,211,238,.18);
}
.hm-note {
  border: 1px solid var(--border); border-radius: 8px;
  padding: 8px 12px; color: var(--text-muted); font-size: .78rem; margin-top: 8px;
}
.hm-legend { display: flex; flex-direction: column; gap: 12px; padding: 8px 4px 0 8px; }
.hm-legend b { font-size: .82rem; }
.hm-legend .hm-muted { font-size: .72rem; margin-top: 2px; }

.hm-agent-head { display: flex; align-items: center; gap: 10px; }
.hm-agent-icon {
  width: 36px; height: 36px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 1rem; flex-shrink: 0;
}
.hm-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 6px; }
.hm-ok { background: var(--earned); box-shadow: 0 0 8px var(--earned); }
.hm-stale { background: var(--sleeper); }
.hm-progress-row { display: flex; align-items: center; gap: 10px; margin: 14px 0 8px; }
.hm-progress { background: var(--elevated); border-radius: 99px; height: 6px; flex: 1; }
.hm-progress > span { display: block; height: 6px; border-radius: 99px; }
.hm-progress-pct { color: var(--text-muted); font-size: .68rem; letter-spacing: .06em; white-space: nowrap; }
.hm-metrics {
  display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
  border-top: 1px solid var(--border); padding-top: 10px; margin-top: 8px;
}
.hm-metrics b { display: block; font-size: 1.15rem; font-variant-numeric: tabular-nums; color: var(--text); }
.hm-metrics span { font-size: .68rem; letter-spacing: .06em; text-transform: uppercase; color: var(--text-muted); }

.hm-footer {
  display: flex; justify-content: space-between; gap: 12px;
  color: var(--text-muted); font-size: .75rem; margin-top: 8px;
}

div[data-testid="stMetric"] {
  background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 8px 10px;
}
.stSelectbox, .stMultiSelect, .stDateInput { font-size: .85rem; }
div[data-testid="stSelectbox"] > div > div,
div[data-testid="stDateInput"] > div > div {
  background: var(--card) !important;
  border: 1px solid var(--border) !important;
  border-radius: 8px !important;
}
div[data-testid="stPlotlyChart"] {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 8px 8px 4px 8px;
  margin-bottom: 16px;
}
</style>
"""


def inject() -> None:
    import streamlit as st

    st.markdown(CSS, unsafe_allow_html=True)


def logo_html(subtitle: str = "") -> str:
    sub = f'<p class="hm-sub">{subtitle}</p>' if subtitle else ""
    return (
        '<div class="hm-brand">'
        f"{FLAME_SVG}"
        "<div>"
        '<p class="hm-title"><span class="hm-humo">Humo</span> vs Miedo</p>'
        f"{sub}"
        "</div></div>"
    )


def header(subtitle: str = "", extra_html: str = "") -> None:
    import streamlit as st

    st.markdown(
        f'<div class="hm-top">{logo_html(subtitle)}<div class="hm-live">{extra_html}</div></div>',
        unsafe_allow_html=True,
    )


def category_badge(name: str) -> str:
    klass = {
        "Overhyped": "hm-cat-overhyped",
        "Earned the hype": "hm-cat-earned",
        "Sleeper": "hm-cat-sleeper",
        "Quiet": "hm-cat-quiet",
    }.get(name, "hm-cat-quiet")
    from html import escape

    return f'<span class="hm-badge {klass}">{escape(name)}</span>'
