# VulnRadar

**Open source dual scoring system (Hype vs Reality) for CVEs, designed for agents and extensible.**

<a href="https://nan.builders/?ref=built-with-nan">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://nan.builders/badge/built-with-nan-light.svg">
    <img width="266" src="https://nan.builders/badge/built-with-nan-dark.svg" alt="Built with NaN">
  </picture>
</a>

**Demo:** https://vulnradar.munalabs.eu · **Repo:** https://github.com/nicoarias81/vulnradar

Base open source version. An asset context layer (inventory + criticality) is
planned; its tables and integration proposal are included, but the runtime
extension is not implemented yet.

## Features

- **Internal mirror** of CVE List V5 (GitHub) + incremental sync
- Transparent and reproducible dual scoring (scoring v4.1)
- Layered architecture: Ingestion → Normalization → Scoring → Context → Output
- Decoupled agents (Sync, Enrichment, Intel, Scoring, Alert)
- 100% open sources (CVE List V5, CISA KEV, FIRST EPSS, RSS, GitHub)
- Extensible architecture, with an asset context integration proposal

## Architecture

```
[CVE List V5 / KEV / EPSS / RSS / GitHub]
              ↓
         Sync Agent + Enrichment Agent
              ↓
         External PostgreSQL
              ↓
         Scoring Agent (scoring v4.1)
              ↓
         [Optional Context layer]  ← the asset inventory plugs in here
              ↓
         API / Dashboard / Alerts
```

## Quick Start

The system is autonomous: a worker in a loop does sync → enrich → intel → score → alert.
There is no need to run agents by hand.

```bash
cp .env.example .env   # DATABASE_URL, LITELLM_API_KEY, webhooks, optional GITHUB_TOKEN
docker compose up --build -d
# Dashboard: http://localhost:8501
docker compose logs -f worker
```

`docker compose up --build -d` brings up **dashboard + worker**. The worker runs
on its own, in a loop (`SYNC_INTERVAL_MINUTES`, default 15):

1. `git fetch --depth 1` + ff-only merge of the CVE List V5 mirror (clone `--depth 1` if missing; if origin rewrote history, `reset --hard` to the remote tip)
2. incremental sync to PostgreSQL
3. enrichment (KEV, EPSS, RSS, GitHub, LLM)
4. structured intelligence (Exploit-DB, CIRCL, GitHub Advisories; daily schedule)
5. scoring
6. alerts (if a webhook is configured)

The UI is served at http://localhost:8501 (seed of 8 CVEs so it does not start
empty; the worker keeps adding real CVEs).

```bash
docker compose down
```

### One-shot local (no Docker)

```bash
pip install -r requirements.txt
python -m core.db
python scripts/run_worker.py          # autonomous loop
# or a single cycle: python scripts/run_worker.py --once
python scripts/run_dashboard.py
# Alternative legacy UI: streamlit run dashboard/app.py
```

The `make sync` / `make enrich` / `make score` targets still exist for debugging.

## Dashboard

The **public** board is at http://localhost:8501: a **Hype vs Reality** scatter
colored by category, a **Pay attention to** table, a table of recent CVEs, a
compact Score evolution timeline and a detail card. It is served by
`python scripts/run_dashboard.py` (or `make dashboard`) on port 8501.

The home page fits on one screen without scrolling: on the left the scatter with
the timeline as a strip at the bottom, on the right **Pay attention to** on top
and **Recent CVEs** below. **Pay attention to** filters by *evidence of
exploitation*, not by CVSS: a CVE enters with KEV, with EPSS ≥ 0.70 or with at
least one public PoC, and the order is KEV → EPSS → PoC. Each row shows the
signals as badges (KEV with the date it was added, PoC count, EPSS) and a Reality
meter. The recent table remains chronological, newest first.

The timeline stretches its axis on its own according to the period maximum. On
the home page it runs in compact mode (no highlights or value axis, three
reference dates); the detail view of each CVE keeps the full version with hover
per day (date, CVEs, Hype, Reality and top CVE) and up to 3 **highlights** with a
vertical guide and chip; those scores are the CVE's, not the axis daily average.
The home page reloads every 60 s without counting as a visit.

The **SOC monitoring** panel (four main agent cards, event feed including Intel,
and logs) lives at
http://localhost:8501/soc and **is not public**. It asks for `SOC_USER` /
`SOC_PASSWORD` from `.env`. Without `SOC_PASSWORD` the login stays closed. The
`Logout` link revokes the session on the server and deletes the cookie. Sessions
use random tokens stored only as SHA-256 hashes in PostgreSQL and expire on the
server after 24 hours. Credential changes invalidate existing sessions. Sessions
work across dashboard slots. Set `SOC_COOKIE_SECURE=1` for HTTPS (enabled by the
production Compose file); use `0` for local HTTP. Previous HMAC cookies require
a new login. The public screen does not link to the SOC.

With an empty database the page does not break: the autonomous worker fills
scores in the next cycle; with `SEED_DEMO=1` there are 8 sample CVEs. Loading and
filtering live in `dashboard/data.py` and are tested with `pytest`. The home page
does not materialize the history: `COUNT(*)` for the total and for the actionable
items, a `LIMIT 400` scatter (prioritizing branding and hype), `LIMIT 6`
actionable items ordered by evidence, a paginated table (`LIMIT/OFFSET`, 6 or 100
in View all) and a timeline with a daily `GROUP BY`.
The SOC panel refreshes itself from the `agent_events` events.

## Incremental sync

Incremental sync is the default mode: what runs every day.

```bash
python agents/sync_agent.py            # incremental (default)
python agents/sync_agent.py --full     # walks the whole mirror
make sync-delta                        # incremental
make sync                              # --full
```

The watermark is the **HEAD SHA of the local git mirror** (`sync_state.cvelist_head`),
not `dateUpdated`: a CVE can be republished without moving its date, and a file
can change because of a metadata fix. On every incremental run:

1. `git fetch --depth 1` + `merge --ff-only` on the mirror (the diff is
   computed **before** the merge: in a shallow clone the old commit may
   disappear afterwards). If origin rewrote `main`, `reset --hard FETCH_HEAD`.
2. If there is no watermark: full walk, even if the DB already contains demo
   rows, enrichment stubs or a partially committed first import.
3. If the watermark matches the pre-fetch local HEAD, use the delta computed
   before the merge. Otherwise compare the stored watermark with the new HEAD.
4. A failed initial import leaves no watermark and is safely retried in full.
5. If HEAD did not change: 0 files, same watermark, exit 0.
6. If it changed: `git diff --name-only OLD NEW` and only the
   `cves/**/*.json` added or modified are processed. Deletions are ignored
   (local rows are not deleted).
7. If the old SHA no longer exists in the mirror (re-clone, rewritten history),
   it degrades to a full walk instead of failing.
8. When done, the current HEAD is stored in `sync_state`.

For tests the mirror and the database can be injected:
`sync(full=False, cve_list_path="...", db_path="...")` or `--cve-list-path`/
`--db-path` through the CLI (`db_path` isolates a test schema; production uses `DATABASE_URL`).

Vendor and product are extracted and normalized during every CVE UPSERT, so
new and modified CVEs participate in product filters without a manual backfill.
For records imported by older releases, run `python scripts/backfill_products.py`
once to populate missing products. If an older release adopted a watermark over
an incomplete catalog, run `python agents/sync_agent.py --full` once: the stored
watermark alone cannot reveal that historical gap.

## Enrichment

`python agents/enrichment_agent.py` runs five signals per CVE: CISA KEV,
EPSS, press mentions (RSS from `config/sources.yaml`), GitHub PoCs and
`tone_score`/branding. Each source writes **only its own columns**, so KEV,
EPSS, media, PoCs and tone coexist in the same `enrichments` row.

Mentions come in two ways. The cycle processes the feeds of the day and,
separately, prioritizes a batch of CVEs (KEV, with a PoC, recent) and searches
each one on Hacker News via Algolia: that is what recovers press for a CVE that
already left the feeds. If a CVE appears in both, the URL dedupes.

`config/sources.yaml` separates two classes of feed. Press and research feeds go
through the LLM, which discards whatever is not a concrete vulnerability and
resolves the CVE from the text. Vendor and CERT advisories (`rss_regex_only`)
already carry the CVE in the headline, so they go through regex, without a
model: 10 feeds of that kind contribute ~600 CVEs in 11 seconds.

RSS dedupes by URL in `media_mentions` (a new URL adds 1 to `media_count`);
PoC counts are stored per source; the compatibility `poc_count` is the maximum, not a deduplicated union; and tone/branding comes from a batch of 10
headlines per call to the configurable LLM (LiteLLM in `config/llm.yaml` +
`core/llm.py`), with a heuristic fallback if the model does not respond or
returns broken JSON.

GitHub checks are recorded in `poc_checks`, including successful empty results.
Positive and empty results become eligible again after 24 hours; failed checks
retry after 15 minutes and preserve the previous count and repositories. HTTP
403/429 also receive one rate-limit retry within the pass. Only a successful
empty GitHub result clears its GitHub repository details; Exploit-DB evidence is preserved. The bounded queue prioritizes
overdue checks, then press coverage, and excludes bare stubs without press.
Repository metrics refresh when checked. Repository details are accumulated
from the first page of search results, except when an empty result clears them.

Flags: `--skip-kev --skip-epss --skip-rss --skip-github --skip-llm`, plus
`--rss-only` (local test) and `--llm-smoke` (one real call to the provider).

## Alerts

`python agents/alert_agent.py` reads the current scores (JOIN `cves` +
`enrichments`) and notifies through Slack and/or a generic webhook. Opt-in rules:
`Overhyped`, `Earned the hype`, `Sleeper` and **baseless hype** (`tone_score >= 7`
with `reality < 5`, tunable with `--humo-tone`/`--humo-reality`).

Channels by environment: `SLACK_WEBHOOK_URL` (incoming webhook, `{text, blocks}`)
and `ALERT_WEBHOOK_URL` (flat JSON, `event: vulnradar.alert`); without a URL, that
channel is skipped. `alerts_sent` dedupes by `UNIQUE(cve_id, channel, rule)` and
is only written **after** a successful POST: a 4xx/5xx leaves the alert pending
for the next run.

```bash
make alerts-dry                      # evaluates and prints: no POST, no writes
python agents/alert_agent.py --once  # real pass (make alerts)
```

## Tests

```bash
pytest -q
```

The tests do not use the network: scoring, normalization, UPSERTs and the
incremental sync are tested against isolated PostgreSQL schemas (`DATABASE_URL` +
`tmp_path` key) and a mini git repo built in the tmp directory itself.

Use a dedicated test database, for example:

```bash
DATABASE_URL=postgresql://user:pass@localhost:5432/vulnradar_test pytest -q
```

Each pytest invocation adds a unique namespace to schema keys, inherited by
multiprocessing children. Cleanup drops only explicitly registered isolation
schemas used by the current process; it never scans a `t_%` wildcard. Regression
tests cover interrupted imports, protected schemas, GitHub failures and refresh
deadlines, bounded incremental scoring, and session expiry/revocation.

## Project structure

```
vulnradar/
├── README.md
├── ARCHITECTURE.md
├── requirements.txt
├── docker-compose.yml
├── .env.example
├── schema.sql
├── agents/
│   ├── sync_agent.py
│   ├── enrichment_agent.py
│   ├── intel_agent.py
│   ├── scoring_agent.py
│   └── alert_agent.py
├── scripts/
│   ├── run_dashboard.py
│   └── run_worker.py          # autonomous loop sync→enrich→intel→score→alert
├── core/
│   ├── scoring.py          # scoring v4.1
│   ├── models.py
│   ├── normalizer.py
│   └── db.py
├── config/
│   └── sources.yaml
├── tests/
│   ├── test_scoring.py
│   ├── test_normalizer.py
│   ├── test_db_upsert.py
│   ├── test_alerts.py
│   ├── test_sync_incremental.py
│   └── test_dashboard.py
└── dashboard/
    ├── data.py             # load + filters (no Streamlit)
    ├── markup.py           # home, detail and SOC panel HTML
    ├── server.py           # HTTP server on 8501
    ├── theme.py            # tokens and visual components
    └── app.py              # Streamlit view (alternative)
```

## Scoring v4.1

The indices are ordinal, not calibrated probabilities or organizational risk.
EPSS remains a separate 0-1 probability with its original date/model version.
See [the current specification and validation](docs/SCORING_V4.md).

- Confirmed exploitation (KEV or a trusted CIRCL reporter):
  `Reality = 7 + ransomware_flag + EPSS` (7-9).
- Otherwise: `Reality = min(5.9, 5*EPSS + public_poc_flag)`.
  GitHub search matches alone do not count as verified public PoC.
- `Hype = 0.60*Media + 0.25*Tone + 0.15*Branding`.
  Media uses distinct recent press stories over 30 days. Advisories/catalogues,
  CVSS and repository counts do not manufacture media attention.
- Missing/stale EPSS without confirmed exploitation is `Unknown`.
- Public PoC or fresh EPSS >= 0.70 without confirmation is `Watch`.
- Confirmed cases are always `Sleeper` or `Earned the hype`, never `Overhyped`.

Versioned input fingerprints, keyset pagination and bulk writes bound scoring
batches to 2,000 rows. `score_all()` and `score_cves()` return recalculated counts.
`score_evaluations` stores exact inputs for every changed fingerprint;
`score_history` stores score/category changes. Bump `SCORING_VERSION` for changes
to formulas, signal mapping or category rules.

The [original audit](docs/SCORING_REVIEW.md) is retained as historical evidence.
`python scripts/audit_scoring.py` now checks its safety requirements independently
of the normal test suite. No empirical claim of predictive improvement is made.

## Real-data local laboratory

```powershell
powershell -File scripts/lab.ps1
# Revalidate persisted data without reloading current sources:
powershell -File scripts/lab.ps1 -ValidateOnly
```

This creates a separate PostgreSQL database and volume (`vulnradar-lab`), runs
regression tests, imports the real mirror, loads public KEV/EPSS/Exploit-DB and
RSS snapshots, computes scores, runs three historical proxy backtests, and
starts the [lab dashboard](http://localhost:18501). No demo rows, alerts or LLM
calls are used. Local SOC credentials: `lab` / `radar-lab-local`.

The lab PostgreSQL port is `localhost:55440`, database/user `radar_lab`, password
`radar_lab_local`. Its dashboard and database ports bind to loopback. Source
bytes, hashes and reports are retained under `data/scoring-lab/`; database data
is in the dedicated Docker volume. Existing local/production databases are not
used by the loader. It refuses database names other than `radar_lab` and requires
`VULNRADAR_LAB=1`.

Cross-platform commands and the measured volume/performance results are in
[the lab runbook](docs/SCORING_LAB.md). Source collection can be partial: the
report records errors and truncated optional sources explicitly. Historical KEV
additions are an imperfect target, not labels for all exploitation.

## Context extension

The proposed **Context** layer would run after Scoring (not implemented yet):

- Load the asset inventory (CSV, API, CMDB)
- Assign criticality (1-10) per asset
- Adjust the final Reality: `Adjusted_Reality = Reality * (criticality / 5.0)`
- Slack alerts when `CVE × critical_asset` crosses the threshold

See `docs/EXTENSION_CONTEXT.md`.

## Open sources used

| Source | Use | URL |
|--------|-----|-----|
| CVE List V5 | Main mirror | https://github.com/CVEProject/cvelistV5 |
| CISA KEV | Strong Reality | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| FIRST EPSS | Probability | https://epss.empiricalsecurity.com/epss_scores-current.csv.gz |
| Security RSS | Media coverage | 25 feeds: THN, BleepingComputer, Talos, Unit 42, Project Zero, watchTowr, etc. |
| Vendor/CERT advisories | Explicit CVE, no LLM | MSRC, Cisco PSIRT, ZDI, Palo Alto, Ivanti, Fortinet, CERT-FR, INCIBE, CERT-EU, Exploit-DB |
| Hacker News (Algolia) | Press for CVEs outside the feeds | https://hn.algolia.com/api |
| GitHub Search | PoCs | Public API |

## Local environment with A/B

`docker-compose.local.yml` brings up PostgreSQL (port 5433), Caddy on
`localhost:8500`, and two dashboard slots against the same database: `a` on
`localhost:8511` and `b` on `localhost:8512`. The slots bind to loopback.
Caddy routes traffic to the active slot. This local Compose file does not start
a worker; run one separately against the local database for live data.

    ./scripts/ab.sh up         # postgres + slot a + proxy on 8500
    ./scripts/ab.sh deploy     # build inactive slot, check health and promote
    ./scripts/ab.sh rollback   # switch traffic back to the other slot
    ./scripts/ab.sh status     # active slot and health

The active slot is recorded in `.ab-active`, which is not versioned. On Windows
with Docker Desktop, prefer `localhost`: some configurations return an empty
reply for IPv4 loopback.

## License

MIT.
