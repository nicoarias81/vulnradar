"""
Dashboard básico con Streamlit
"""
import streamlit as st
import pandas as pd
import plotly.express as px
from core.db import get_db

st.set_page_config(page_title="Humo vs Miedo", layout="wide")
st.title("Humo vs Miedo — Hype vs Reality")

conn = get_db()
df = pd.read_sql("""
    SELECT s.cve_id, s.hype, s.reality, s.category, c.description, c.cvss_score
    FROM scores s
    JOIN cves c ON s.cve_id = c.cve_id
    WHERE s.id IN (SELECT MAX(id) FROM scores GROUP BY cve_id)
    ORDER BY s.calculated_at DESC
    LIMIT 500
""", conn)

col1, col2 = st.columns([2, 1])

with col1:
    fig = px.scatter(
        df, x="hype", y="reality", color="category",
        hover_data=["cve_id", "cvss_score"],
        title="Hype vs Reality"
    )
    fig.add_shape(type="line", x0=0, y0=0, x1=10, y1=10, line=dict(dash="dash"))
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.dataframe(df[["cve_id", "hype", "reality", "category"]].head(20))

st.subheader("Detalle")
selected = st.selectbox("Seleccionar CVE", df["cve_id"])
if selected:
    st.write(df[df.cve_id == selected].iloc[0])
