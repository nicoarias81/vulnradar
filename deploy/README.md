# VulnRadar deployment

Production uses `deploy/docker-compose.server.yml`: Cloudflare Tunnel forwards
to Caddy on `127.0.0.1:8501`, which routes to the active dashboard slot.
Dashboard A and B are available for inspection on loopback ports 8511 and 8512.
The worker runs sync -> enrich -> intel -> score -> alert independently of slots.
This runbook describes repository configuration, not a live health report.

## Configuration

- Code directory: `/opt/vulnradar`; persistent mirror: `/opt/vulnradar/data`.
- Secrets: `/opt/vulnradar/deploy/.env.prod`, permissions `600`.
- External PostgreSQL: `DATABASE_URL`; external Docker networks: `db` and
  `internal` (LiteLLM), plus the Compose default network for outbound traffic.
- LiteLLM endpoint: `http://litellm:4000/v1`; select model/key through the env file.
- `SEED_DEMO=0` in both production slots.
- `/soc`, `/agentes` and `/agents` require `SOC_USER`/`SOC_PASSWORD`. Without a
  password, access stays closed. `/` and `/cve` remain public.
- Production sets `SOC_COOKIE_SECURE=1`: access SOC over HTTPS through the
  tunnel. A Secure cookie is not sent over a direct HTTP inspection URL.

## Deploy

```bash
bash deploy/deploy.sh
```

The script performs preflight checks, transfers the source, bootstraps server
configuration, builds the inactive slot, checks health and switches Caddy traffic.
The worker is recreated against the new image before the dashboard promotion.
Use `--from-worktree` for uncommitted changes, `--allow-dirty` to deploy committed
HEAD from a dirty checkout, `--no-build` to skip the explicit production image
build, and `--skip-cloudflare` to omit tunnel/DNS reconciliation. The A/B helper
still builds its candidate during promotion. The mirror and env file are
persistent server data and must not be overwritten by source transfer.

Local A/B commands use `scripts/ab.sh`; `deploy/deploy.sh` supplies production
paths and configuration. Local proxy is port 8500; production proxy is 8501.

## Upgrade behavior

`init_db()` applies additive schema changes at startup. This release adds
`scores.input_hash`, `poc_checks` and `soc_sessions` and ensures vendor/product
columns exist. `pg_trgm` is installed in `public` for shared index visibility.
The database role must be allowed to apply these changes; inspect startup logs
and verify schema readiness before promoting a slot.

- Existing scores are recalculated once to populate versioned fingerprints.
  Subsequent passes only recalculate changed inputs in batches of 2,000.
- Category correction: Reality >= 6 and Hype < 6 is `Sleeper`, including the
  previous gap at Hype 5-6. Category-only changes enter `score_history`.
- Old HMAC SOC cookies require a new login. New sessions expire after 24 hours
  on the server, are shared across slots and are revoked at logout. Password or
  username changes invalidate existing sessions.
- Old PoC records are eligible for a fresh check. Successful checks (including
  empty results) refresh after 24 hours. Failures preserve evidence and retry
  after 15 minutes.
- New and modified CVEs populate vendor/product during ingestion. Populate
  missing products in historical records once with:

  ```bash
  python scripts/backfill_products.py
  ```

- Missing sync watermark triggers a full import, including after an interrupted
  initial load. If an older version already adopted a watermark over an
  incomplete catalog, explicitly repair it once:

  ```bash
  python agents/sync_agent.py --full
  ```

  Run these commands inside the worker container or a configured environment
  against the intended production database. They update data. Stop the regular
  worker during a full repair to avoid simultaneous mirror updates.

## First boot and health

The first cycle clones CVE List V5 and imports the full catalog before enriching
and scoring. It can take longer than `SYNC_INTERVAL_MINUTES`; that setting is
the sleep after each cycle, not a hard scheduling deadline.

```bash
docker compose -f deploy/docker-compose.server.yml --env-file deploy/.env.prod ps
docker compose -f deploy/docker-compose.server.yml --env-file deploy/.env.prod logs --tail 50 worker
curl -f http://localhost:8501/health
curl -f https://vulnradar.munalabs.eu/
```

`/health` checks that the HTTP server is responding. It does not verify database
connectivity, schema completeness, freshness or worker progress. Inspect
`agent_events` or the authenticated SOC panel for pipeline health.

## Operations and tests

Use `deploy/backup-db.sh` for PostgreSQL backups and check its configured backup
directory and retention before scheduling it. Use a dedicated PostgreSQL test
database. Test schemas have a per-invocation namespace and cleanup only targets
explicitly registered schemas.

The image excludes `.env*` and `deploy/` through `.dockerignore`; production
secrets are injected through the env file. Public dashboard errors return a
generic response, while exception details remain in server logs. Containers
currently run as root inside the image. Deployment readiness should include
schema logs and worker progress as well as HTTP health.

## Scoring v4.1 upgrade

Apply `schema.sql` through `init_db()` before running new workers: this adds
source observations, source health, separate PoC counters, EPSS metadata,
attention refresh deadlines and `score_evaluations`. Schema errors now prevent
startup. Numeric constraints apply to new/changed rows; legacy constraints are
installed `NOT VALID` so old bad data must be audited/recomputed before validation.

The scoring version bump invalidates old fingerprints. Refresh real sources and
recalculate scores before judging changed categories; old aggregate counters and
untyped mentions do not establish source provenance. Missing/stale EPSS becomes
Unknown, curated public PoC/high EPSS becomes Watch, and confirmed exploitation
has a Reality floor of 7. Add `CIRCL_TRUSTED_AUTHORS` only after reviewing reporter
identities. An empty allowlist preserves reports without asserting confirmation.

Reality is an ordinal index; the new tier thresholds and attention weights are
explicit safety/product rules, not fitted probabilities. The real-data lab and
three-cohort KEV proxy backtest are documented under `docs/SCORING_LAB.md`.
Production has not been deployed by the lab scripts.
