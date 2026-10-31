# Makefile simple

.PHONY: init sync enrich score dashboard

init:
	python -m core.db

sync:
	python agents/sync_agent.py --full

enrich:
	python agents/enrichment_agent.py

score:
	python agents/scoring_agent.py

dashboard:
	streamlit run dashboard/app.py

all: init sync enrich score
