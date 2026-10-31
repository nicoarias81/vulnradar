# Makefile simple

.PHONY: init sync sync-delta enrich score test dashboard

init:
	python -m core.db

sync:
	python agents/sync_agent.py --full

# Delta: sólo los cves/**/*.json que cambiaron desde el último HEAD del mirror.
sync-delta:
	python agents/sync_agent.py

enrich:
	python agents/enrichment_agent.py

score:
	python agents/scoring_agent.py

test:
	python -m pytest -q

dashboard:
	streamlit run dashboard/app.py

all: init sync enrich score
