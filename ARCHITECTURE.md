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
Applies scoring v4.1. Produces Hype, Reality and category.
Versioned input fingerprints select only changed inputs. Keyset pagination and
bulk writes bound each batch to 2,000 rows. `scores` stores the current values;
`score_history` stores numerical and category changes. Confirmed exploitation has Reality >= 7 and is always
`Sleeper` (Hype < 6) or `Earned the hype` (Hype ≥ 6).

### 4. Asset context (optional)
- Asset inventory
- Criticality per asset
- Adjustment of the final score
- CVE → affected assets mapping

### 5. Output
- HTML dashboard using `ThreadingHTTPServer` (Streamlit is an alternative UI)
- Product autocomplete JSON endpoint (`/api/products`)
- Alerts (Slack and generic webhook)
- SOC panel with PostgreSQL-backed expiring, revocable sessions

### Autonomous worker
`scripts/run_worker.py` (the `worker` service in Compose) runs in a loop:
incremental sync → enrich → intel → score → alert. Interval: `SYNC_INTERVAL_MINUTES`
(default 15). A step that fails does not cancel the following ones. The Agents
dashboard reads `agent_events`. No manual commands required.

An absent sync watermark always triggers a full import; demo/stub rows and a
pull delta cannot prove catalog completeness. The watermark is stored after
processing the planned files. Vendor/product normalization is part of ingestion.
GitHub checks have a persisted deadline, including zero-result checks: successes
refresh after 24 hours and failures retry after 15 minutes without deleting
previous evidence. Intel collects Exploit-DB, CIRCL sightings and GitHub Advisories
on its own daily schedule.

`schema.sql` contains additive, idempotent upgrades (`ALTER TABLE ... ADD COLUMN
IF NOT EXISTS`) as well as new tables. Both dashboard and worker apply it at
startup. The asset context layer remains a proposed extension, not an implemented
runtime plugin; `assets` and `cve_assets` are placeholders for that integration.

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

## Scoring v4.1 evidence model

`evidence` keeps source-local artifact/sighting/tone observations. GitHub and
Exploit-DB counters are separate; their compatibility maximum is not a unique
exploit count. CIRCL reports require an explicitly trusted author UUID before
setting `wild_confirmation`. Missing/stale prediction is `Unknown`; unconfirmed
public PoC or high fresh EPSS is `Watch`.

Press, advisories and catalogues are typed separately. The scoring SQL aggregates
deduplicated press stories over 30 days and expires EPSS after seven days.
CVSS and GitHub popularity do not contribute to attention. `score_evaluations`
retains exact normalized inputs, algorithm version, source metadata and output
for each changed fingerprint, even if rounded values remain unchanged.

`source_runs` records source-level SUCCESS/PARTIAL/ERROR, and Intel has independent
watermarks. Source failure does not cancel unrelated sources. Schema failures
abort startup rather than announcing readiness with missing tables/constraints.
See `docs/SCORING_V4.md` and `docs/SCORING_LAB.md` for semantics and validation.
