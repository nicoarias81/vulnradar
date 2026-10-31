"""
Dashboard Streamlit — Humo vs Miedo.

Tres pantallas alineadas a los mockups: overview (scatter + tabla + timeline),
ficha de CVE y panel de agentes. La carga vive en `dashboard.data`.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st

from dashboard.screens import agents, detail, overview

st.set_page_config(
    page_title="Humo vs Miedo",
    layout="wide",
    initial_sidebar_state="collapsed",
)

page = st.navigation(
    {
        "Humo vs Miedo": [
            st.Page(overview, title="Dashboard", icon="🔥", default=True),
            st.Page(detail, title="CVE", icon="🎯"),
            st.Page(agents, title="Agentes", icon="📡"),
        ]
    }
)
page.run()
