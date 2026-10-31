# Makefile simple

.PHONY: init sync sync-delta enrich score alerts alerts-dry test dashboard demo demo-down

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

# Una pasada de alertas: envía sólo lo que no esté en alerts_sent.
alerts:
	python agents/alert_agent.py --once

# Ensayo: evalúa e imprime, sin POST ni escrituras.
alerts-dry:
	python agents/alert_agent.py --dry-run

test:
	python -m pytest -q

dashboard:
	streamlit run dashboard/app.py

demo:
	docker compose up --build -d
	@echo Dashboard: http://localhost:8501

demo-down:
	docker compose down

all: init sync enrich score
