"""
Dashboard Streamlit — Humo vs Miedo.

La carga y el filtrado viven en `dashboard/data.py` (stdlib puro) para poder
testearlos con pytest sin el runtime de Streamlit.
"""
import sys
from collections import Counter
from pathlib import Path

# `streamlit run` agrega sólo dashboard/ al sys.path: la raíz del repo hace
# falta para importar `core` y `dashboard.data`.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import plotly.express as px
import streamlit as st

from core.db import get_db
from dashboard.data import CATEGORIES, filter_scores, load_scores

st.set_page_config(page_title="Humo vs Miedo", layout="wide")
st.title("Humo vs Miedo — Hype vs Reality")

conn = get_db()
try:
    rows = load_scores(conn)
finally:
    conn.close()

# Empty state: sin scores no hay nada que graficar ni elegir.
if not rows:
    st.warning(
        "La base no tiene scores todavía. Corré, en orden:\n\n"
        "1. `python -m core.db`\n"
        "2. `python agents/sync_agent.py --full`\n"
        "3. `python agents/enrichment_agent.py`\n"
        "4. `python agents/scoring_agent.py`\n\n"
        "(`make all` hace 1, 2, 3 y 4 de una.)"
    )
    st.stop()

# Filtros en la barra lateral. Multiselect vacío = sin filtro de categoría.
categories = st.sidebar.multiselect(
    "Categoría", list(CATEGORIES), default=list(CATEGORIES)
)
min_hype = st.sidebar.slider("Hype mínimo", 0.0, 10.0, 0.0, 0.1)
min_reality = st.sidebar.slider("Reality mínimo", 0.0, 10.0, 0.0, 0.1)

filtered = filter_scores(rows, categories, min_hype, min_reality)

counts = Counter(row["category"] for row in filtered)
for column, name in zip(st.columns(len(CATEGORIES)), CATEGORIES):
    column.metric(name, counts.get(name, 0))
st.caption(f"{len(filtered)} de {len(rows)} CVEs scoreados")

if not filtered:
    st.info("Ningún CVE pasa los filtros actuales.")
    st.stop()

df = pd.DataFrame(filtered)

left, right = st.columns([2, 1])

with left:
    st.subheader("Hype vs Reality")
    fig = px.scatter(
        df, x="hype", y="reality", color="category",
        hover_data={
            "cve_id": True, "cvss_score": True, "tone_score": True,
            "hype": ":.2f", "reality": ":.2f",
        },
        range_x=[0, 10], range_y=[0, 10],
    )
    # Diagonal x=y: arriba sólo humo, abajo miedo con poca prensa.
    fig.add_shape(
        type="line", x0=0, y0=0, x1=10, y1=10,
        line=dict(dash="dash", color="gray"),
    )
    st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Scores")
    st.dataframe(
        df[[
            "cve_id", "category", "hype", "reality",
            "cvss_score", "tone_score", "alertado",
        ]],
        hide_index=True,
        use_container_width=True,
    )

st.subheader("Detalle")
selected = st.selectbox("CVE", df["cve_id"].tolist())
detail = df[df["cve_id"] == selected].iloc[0]

for column, label, value in zip(
    st.columns(4),
    ("Hype", "Reality", "CVSS", "Alertado"),
    (
        f"{detail.hype:.2f}",
        f"{detail.reality:.2f}",
        "n/d" if pd.isna(detail.cvss_score) else f"{detail.cvss_score:.1f}",
        f"sí ({int(detail.alertas)})" if detail.alertado else "no",
    ),
):
    column.metric(label, value)

st.write(
    f"**{detail.cve_id}** — {detail.category} · "
    f"severidad {detail.cvss_severity or 'n/d'}"
)
st.write(detail.description or "_(sin descripción sincronizada)_")

with st.expander("Señales de enriquecimiento"):
    st.write({
        "tone_score": detail.tone_score,
        "media_count": detail.media_count,
        "in_kev": bool(detail.in_kev),
        "epss": detail.epss,
        "poc_count": detail.poc_count,
        "branding": bool(detail.branding),
        "brand_name": detail.brand_name,
        "calculated_at": detail.calculated_at,
    })
