# Architecture — VulnRadar

## Design principles

1. **Decoupled layers**: each layer only knows the normalized schema.
2. **Extensible**: new sources or the Context layer are added without touching the core.
3. **Reproducible**: scoring is deterministic and auditable.
4. **Agents**: each responsibility is an independent process.

## Layers

### 1. Ingestion
- Sync Agent: git pull of CVE List V5 + delta
- Enrichment Agent: KEV, EPSS, RSS, GitHub PoCs

### 2. Normalization
Single internal schema:

```json
{
  "cve_id": "CVE-2026-XXXXX",
  "published": "2026-...",
  "cvss": 9.8,
  "signals": {
    "in_kev": true,
    "epss": 0.87,
    "media_count": 12,
    "poc_count": 5,
    "tone_score": 8.0,
    "branding": true
  }
}
```

### 3. Scoring
Applies the v2 formulas. Produces Hype, Reality and category.

### 4. Asset context (optional)
- Asset inventory
- Criticality per asset
- Adjustment of the final score
- CVE → affected assets mapping

### 5. Output
- REST API
- Dashboard (Streamlit)
- Alerts (Slack, webhook, email)

### Autonomous worker
`scripts/run_worker.py` (the `worker` service in Compose) runs in a loop:
incremental sync → enrich → score → alert. Interval: `SYNC_INTERVAL_MINUTES`
(default 15). A step that fails does not cancel the following ones. The Agents
dashboard reads `agent_events`. No manual commands required.

## Data flow

```
CVE List V5 ──┐
CISA KEV     ──┤
EPSS         ──┼→ Enrichment → PostgreSQL → Scoring → [Context] → Dashboard/Alerts
RSS + GitHub ──┘
```

## Future extensions

- New sources: add a feeder in the Enrichment Agent
- Asset context: implement `core/context.py` and call it after scoring
- New alert channels: add them in the Alert Agent
