"""
Dashboard Humo vs Miedo.

La UI es HTML servido por `dashboard.server` (puerto 8501). Streamlit ya no
pinta las pantallas: el CSS de los mockups no sobrevive a su layout.
"""
from dashboard.server import main

if __name__ == "__main__":
    raise SystemExit(main())
