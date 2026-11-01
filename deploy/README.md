# VulnRadar deploy (public) — personal-1

`https://vulnradar.munalabs.eu` — **public** site, served by Cloudflare Tunnel, no open ports.

```
Internet → Cloudflare edge → tunnel "personal-1" → http://localhost:8501 → container vulnradar-dashboard-1
                                                                        ↘ container vulnradar-worker-1 (sync→enrich→score→alert)
```

| | |
|---|---|
| Server | Hetzner CAX21 ARM64, `ssh.munalabs.eu` (tunnel only) |
| Code | `/opt/vulnradar` (not a git repo: it is synced with `git archive HEAD`) |
| Data | `/opt/vulnradar/data` (bind mount): `cvelistV5` mirror. DB = external PostgreSQL (`DATABASE_URL`) |
| Secrets | `/opt/vulnradar/deploy/.env.prod` (chmod 600, generated on the server, never in the repo) |
| Port | `127.0.0.1:8501` — nothing listens on 0.0.0.0 |
| Networks | `default` (egress: git/CISA/EPSS/RSS/GitHub) + `internal` (shared LiteLLM from `/opt/stack`) |
| LLM | `LLM_BASE_URL=http://litellm:4000/v1`, model `qwen3.8-flash`, key = LiteLLM virtual key |
| SOC panel | `/soc` with `SOC_USER`/`SOC_PASSWORD` (HMAC cookie). Without a password the panel stays closed |
| Access | **no** Cloudflare Access: the site is public on purpose |

## Deploy (when the code is ready)

```bash
bash deploy/deploy.sh            # requires a clean tree; aborts otherwise
```

It does, in order: preflight (clean git + SSH + disk) → `git archive HEAD` to the server → CRLF normalization →
bootstrap (`/opt/vulnradar/data`, `.env.prod` if missing) → env checks without printing values →
`docker compose up -d --build` → ingress + DNS in Cloudflare → verification (local and public).

Flags: `--from-worktree` (deploys the uncommitted working tree), `--allow-dirty` (deploys HEAD even with
uncommitted changes), `--no-build` (recreate only, for an env change), `--skip-cloudflare`.

> Note: `git archive HEAD` does **not** include untracked files. If `deploy/` is not committed, the script
> aborts and asks you to commit or use `--from-worktree`.

## State when this runbook was prepared (verified)

- `/opt/vulnradar` exists with the code + `deploy/`; `/opt/vulnradar/data` empty (4 KB).
- `deploy/.env.prod` created, `chmod 600`, `SOC_PASSWORD` of 32 random hex chars, `LITELLM_API_KEY` copied
  server-side from `/opt/panopticon/deploy/.env.prod` (hash matches; that key already answers 200 with
  `qwen3.8-flash` on `litellm:4000`).
- `docker compose -f deploy/docker-compose.server.yml --env-file deploy/.env.prod config --quiet` → valid.
- Ingress + DNS **created** (`vulnradar.munalabs.eu` → `http://localhost:8501`, CNAME proxied to the tunnel,
  catch-all untouched, no Access app). Previous ingress backup: `/root/cf-backups/tunnel-ingress-*.json`.
- **Deployed and in production** (dashboard healthy, worker completing cycles, public site 200).

### Verification notes from this machine

- The Windows resolver can keep a cached NXDOMAIN for the freshly created domain: a normal `curl` returns
  000 even though `nslookup` against 1.1.1.1 resolves. Use `--resolve vulnradar.munalabs.eu:443:<edge IP>`
  (`deploy.sh` already does) or flush DNS in an elevated console.
- From the server, `curl https://*.munalabs.eu` returns 403 (Cloudflare filter on datacenter IPs:
  the same happens with `hermes.munalabs.eu`). It is useless as an availability check; verify from another network.

## Steps one by one

```bash
# 1. code (without touching data/ or .env.prod)
git archive --format=tar HEAD | ssh ... 'tar -x -C /opt/vulnradar'

# 2. dirs + env.prod (idempotent)
ssh ... 'bash /opt/vulnradar/deploy/bootstrap-server.sh'

# 3. build + up
ssh ... 'cd /opt/vulnradar && docker compose -f deploy/docker-compose.server.yml --env-file deploy/.env.prod up -d --build'

# 4. ingress + DNS (public: no Access app)
ssh ... 'set -a; source /opt/cloudflare/credentials.env; set +a; python3 -' < deploy/cloudflare-vulnradar.py
```

## Verification

```bash
ssh ... "curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8501/health"        # 200
ssh ... "curl -s http://127.0.0.1:8501/soc | grep -c 'SOC MONITORING'"                  # 0 (login)
curl -s -A "Mozilla/5.0" -o /dev/null -w '%{http_code}\n' https://vulnradar.munalabs.eu/  # 200
ssh ... 'docker logs --tail 30 vulnradar-worker-1'
```

Expected on `/soc` without a cookie: the login page (200). With a cookie: the `SOC MONITORING` panel.

## First boot (important)

`SEED_DEMO=0`: the DB starts empty and **the worker fills it by itself**. The first cycle is expensive:

1. `git clone --depth 1` of the cvelistV5 mirror (~1–2 GB on disk).
2. Full walk of ~395k JSON files → PostgreSQL.
3. Enrichment per cycle: full KEV + EPSS, RSS, PoCs for 25 CVEs, tone for 50 CVEs (batches of 10).
4. Scoring over the enriched CVEs.

In other words: the public site starts showing little and fills up over time. A cycle can last longer than
`SYNC_INTERVAL_MINUTES=15`; the loop simply sleeps when it finishes. Tracking:

```bash
ssh ... 'docker logs -f --tail 50 vulnradar-worker-1'
ssh ... "docker exec vulnradar-dashboard-1 python -c \"from core.db import get_db;c=get_db();print([(t,c.execute('select count(*) from '+t).fetchone()[0]) for t in ('cves','scores','enrichments')]);c.close()\""
```

## Operations

```bash
# logs
ssh ... 'docker logs -f --tail 100 vulnradar-dashboard-1'
# PostgreSQL backup (pg_dump) + rotation (suggested cron 04:00)
ssh ... 'bash /opt/vulnradar/deploy/backup-db.sh'
# SOC panel credentials
ssh ... 'grep -E "^SOC_(USER|PASSWORD)=" /opt/vulnradar/deploy/.env.prod'
# code rollback to a previous commit
git archive --format=tar <sha> | ssh ... 'tar -x -C /opt/vulnradar'   # + up -d --build
# shut down
ssh ... 'cd /opt/vulnradar && docker compose -f deploy/docker-compose.server.yml down'
```

## Security notes

- `.dockerignore` excludes `.env*` and `deploy/`: the image does **not** carry `.env.prod` (verified with a marker).
- The code escapes everything coming from the DB with `html.escape()` (RSS titles, CVE descriptions).
- The only writable endpoint is `POST /soc` (login); the rest is read-only.
- Containers run as root inside the image (default); no ports published beyond 127.0.0.1.

## Open items/decisions at the time of this runbook

- Confirm the public scope: today anyone can read `/`, `/cve`, `/agentes`; `/soc` asks for a password.
- LLM smoke test in prod (that the virtual key enables `qwen3.8-flash`); otherwise tone falls back to the heuristic.
- The overview needs **scored** CVEs; until the worker completes cycles, the home page looks empty.
