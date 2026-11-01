"""
VulnRadar dashboard.

The UI is HTML served by `dashboard.server` (port 8501). Streamlit no longer
renders the screens: the mockup CSS does not survive its layout.
"""
from dashboard.server import main

if __name__ == "__main__":
    raise SystemExit(main())
