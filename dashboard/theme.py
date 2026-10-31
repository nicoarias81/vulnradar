"""Look & feel de los mockups: fondo navy, naranja Humo, cyan Reality."""

CATEGORY_COLORS = {
    "Overhyped": "#f43f5e",
    "Sleeper": "#eab308",
    "Earned the hype": "#22c55e",
    "Quiet": "#94a3b8",
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

SEVERITY_COLORS = {
    "CRITICAL": "#f43f5e",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#94a3b8",
}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@500;600&display=swap');

html, body, [data-testid="stAppViewContainer"], .stApp {
  background: #070b14 !important;
  color: #e8eef7 !important;
  font-family: "IBM Plex Sans", "Segoe UI", sans-serif !important;
}
[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stToolbar"], #MainMenu, footer, [data-testid="stDecoration"] {
  visibility: hidden; height: 0;
}
.block-container { padding-top: 1.1rem !important; max-width: 1280px !important; }

.hm-top {
  display: flex; align-items: center; justify-content: space-between;
  gap: 16px; margin-bottom: 18px; flex-wrap: wrap;
}
.hm-brand { display: flex; align-items: center; gap: 10px; }
.hm-flame {
  width: 36px; height: 36px; border-radius: 10px;
  background: radial-gradient(circle at 40% 30%, #ffb347, #ff6a00 55%, #c2410c);
  box-shadow: 0 0 18px rgba(255,106,0,.45);
}
.hm-title { font-size: 1.45rem; font-weight: 700; letter-spacing: .02em; margin: 0; }
.hm-title span { color: #ff6a00; }
.hm-sub { color: #8b9bb4; font-size: .85rem; margin: 0; }

.hm-card {
  background: #10182a;
  border: 1px solid #1e2a44;
  border-radius: 14px;
  padding: 16px 18px;
  margin-bottom: 12px;
}
.hm-card h3 {
  font-size: .78rem; letter-spacing: .08em; text-transform: uppercase;
  color: #9fb0c9; margin: 0 0 4px 0; font-weight: 600;
}
.hm-muted { color: #7f8da3; font-size: .8rem; }

.hm-badge {
  display: inline-block; padding: 2px 8px; border-radius: 999px;
  font-size: .72rem; font-weight: 600; letter-spacing: .04em;
}
.hm-link { color: #60a5fa; text-decoration: none; font-family: "IBM Plex Mono", monospace; font-weight: 600; }
.hm-link:hover { text-decoration: underline; }

.hm-table { width: 100%; border-collapse: collapse; font-size: .86rem; }
.hm-table th {
  text-align: left; color: #7f8da3; font-size: .7rem; letter-spacing: .08em;
  text-transform: uppercase; padding: 8px 6px; border-bottom: 1px solid #1e2a44;
}
.hm-table td { padding: 10px 6px; border-bottom: 1px solid #162033; vertical-align: middle; }
.hm-table tr:hover td { background: #141c30; }

.hm-bar-wrap { background: #1a2438; border-radius: 6px; height: 8px; width: 100%; }
.hm-bar { height: 8px; border-radius: 6px; background: linear-gradient(90deg, #ff6a00, #fb923c); }

.hm-score {
  font-size: 3.2rem; font-weight: 700; line-height: 1; font-family: "IBM Plex Mono", monospace;
}
.hm-score small { font-size: 1rem; color: #7f8da3; }
.hm-hype { color: #fb923c; }
.hm-reality { color: #22d3ee; }

.hm-banner {
  border: 1px solid #fb923c55; background: #1a1208; border-radius: 12px;
  padding: 14px 16px; margin-top: 12px;
}
.hm-banner strong { color: #fb923c; letter-spacing: .06em; }

.hm-agent {
  display: flex; justify-content: space-between; gap: 8px; align-items: flex-start;
}
.hm-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 6px; }
.hm-ok { background: #22c55e; box-shadow: 0 0 8px #22c55e; }
.hm-stale { background: #eab308; }

div[data-testid="stMetric"] {
  background: #10182a; border: 1px solid #1e2a44; border-radius: 12px; padding: 8px 10px;
}
</style>
"""


def inject() -> None:
    import streamlit as st

    st.markdown(CSS, unsafe_allow_html=True)


def header(subtitle: str = "Datos contra el ruido.", extra_html: str = "") -> None:
    import streamlit as st

    st.markdown(
        f"""
        <div class="hm-top">
          <div class="hm-brand">
            <div class="hm-flame"></div>
            <div>
              <p class="hm-title"><span>Humo</span> vs Miedo</p>
              <p class="hm-sub">{subtitle}</p>
            </div>
          </div>
          <div class="hm-sub">{extra_html}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
