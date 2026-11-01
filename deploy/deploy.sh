#!/usr/bin/env bash
# Deploy VulnRadar to personal-1 (Hetzner CAX21, ARM64) over a Cloudflare Tunnel.
#
#   bash deploy/deploy.sh                   # deploy completo (exige tree limpio y deploy/ commiteado)
#   bash deploy/deploy.sh --from-worktree    # deploya el working tree actual (sin commitear)
#   bash deploy/deploy.sh --allow-dirty      # deploy HEAD even with uncommitted changes
#   bash deploy/deploy.sh --no-build         # recreate only (env changes, not code)
#   bash deploy/deploy.sh --skip-cloudflare  # sin tocar ingress/DNS
#
# Code travels as a tarball (the server is NOT a git repo). `data/` and `deploy/.env.prod` are never overwritten.
set -euo pipefail

REMOTE_HOST=root@ssh.munalabs.eu
REMOTE=/opt/vulnradar
KEY="$HOME/.ssh/id_ed25519"
CLOUDFLARED="C:/Program Files (x86)/cloudflared/cloudflared.exe"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRLF='s/\r$//'

ALLOW_DIRTY=0
BUILD=1
CF=1
FROM_WORKTREE=0
for arg in "$@"; do
  case "$arg" in
    --allow-dirty) ALLOW_DIRTY=1 ;;
    --from-worktree) FROM_WORKTREE=1 ;;
    --no-build) BUILD=0 ;;
    --skip-cloudflare) CF=0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

ssh_srv() {
  ssh -o BatchMode=yes -o ConnectTimeout=20 -o StrictHostKeyChecking=accept-new \
      -o "ProxyCommand=\"$CLOUDFLARED\" access ssh --hostname %h" \
      -i "$KEY" "$REMOTE_HOST" "$@"
}

# Timestamp on every step: without it there is no telling which part of the deploy eats the
# ~2 min the site spends down.
step() { printf '\n== %s  [%s]\n' "$*" "$(date +%H:%M:%S)"; }

step "preflight"
cd "$REPO"
if [ "$FROM_WORKTREE" -eq 0 ]; then
  if [ "$ALLOW_DIRTY" -eq 0 ] && [ -n "$(git status --porcelain)" ]; then
    echo "dirty tree: commit or use --allow-dirty / --from-worktree" >&2
    git status --short >&2
    exit 1
  fi
  if ! git cat-file -e HEAD:deploy/docker-compose.server.yml 2>/dev/null; then
    echo "deploy/ is not committed in HEAD: commit it or use --from-worktree" >&2
    exit 1
  fi
  echo "source: HEAD $(git rev-parse --short HEAD)"
else
  echo "source: working tree (uncommitted)"
fi
ssh_srv 'echo ssh: ok; docker --version; df -h / | awk "NR==2{print \"free disk: \"\$4}"'

step "code sync"
ssh_srv "mkdir -p $REMOTE"
if [ "$FROM_WORKTREE" -eq 1 ]; then
  tar -c -f - -C "$REPO" \
      --exclude=.git --exclude=.venv --exclude=venv --exclude=data \
      --exclude=.pytest_tmp --exclude=.pytest_cache --exclude=__pycache__ \
      --exclude=.env --exclude=deploy/.env.prod --exclude=.grok --exclude=.atl . \
    | ssh_srv "tar -x -C $REMOTE"
else
  git archive --format=tar HEAD | ssh_srv "tar -x -C $REMOTE"
fi
ssh_srv "find $REMOTE/deploy $REMOTE/scripts -type f \( -name '*.sh' -o -name '*.yml' -o -name '*.py' \) -print0 | xargs -0 -r sed -i '$CRLF' && echo extract+crlf: ok"

step "bootstrap (dirs + env.prod if missing)"
ssh_srv "bash $REMOTE/deploy/bootstrap-server.sh"

step "env checks (values not printed)"
ssh_srv "grep -q '^SOC_PASSWORD=.' $REMOTE/deploy/.env.prod && echo 'soc: password set' || { echo 'soc: SOC_PASSWORD empty in .env.prod -> aborted' >&2; exit 1; }"
ssh_srv "grep -q '^LITELLM_API_KEY=.' $REMOTE/deploy/.env.prod && echo 'llm: key present' || echo 'llm: NO key -> tone/branding fall back to heuristic'"

step "cleanup of old project orphans"
# Containers from an earlier compose keep the name `<hash>_vulnradar-<svc>` and stay
# stuck on the service name: `up` recognises them, leaves them in `created`
# and starts nothing. They are removed before bringing anything up.
ssh_srv "docker ps -a --format '{{.Names}}' | grep -E '^[0-9a-f]{12}_vulnradar-' | xargs -r docker rm -f 2>&1 | tail -5 || true"

step "base services (proxy, active slot untouched)"
# The active dashboard is NOT recreated here: the blue-green switch below replaces it.
ssh_srv "cd $REMOTE && docker compose -f deploy/docker-compose.server.yml --env-file deploy/.env.prod up -d --no-deps proxy 2>&1 | tail -6"

step "blue-green (candidate in parallel, traffic untouched until it responds)"
# Build BEFORE bringing up: compiling inside `up` leaves the container down.
# ab.sh starts the idle slot, waits for its /health (up to 4 min) and only then
# moves traffic with an atomic Caddy reload; if the candidate does not answer,
# the site keeps serving from the previous slot.
if [ "$BUILD" -eq 1 ]; then
  ssh_srv "cd $REMOTE && docker compose -f deploy/docker-compose.server.yml build 2>&1 | tail -8"
fi
# The worker shares the image with the slots but does not go through blue-green:
# recreating it before the build left it running the previous code and
# overwriting the new scores on every cycle. It always goes after the build.
ssh_srv "cd $REMOTE && docker compose -f deploy/docker-compose.server.yml --env-file deploy/.env.prod up -d --no-deps --force-recreate worker 2>&1 | tail -6"
ssh_srv "cd $REMOTE && COMPOSE_FILE=deploy/docker-compose.server.yml ENV_FILE=deploy/.env.prod PROXY_PORT=8501 SLOT_A_PORT=8511 SLOT_B_PORT=8512 STATE_FILE=$REMOTE/.ab-active bash scripts/ab.sh deploy"

step "cloudflare (ingress + public DNS)"
if [ "$CF" -eq 1 ]; then
  ssh_srv 'set -a; source /opt/cloudflare/credentials.env; set +a; python3 -' < "$REPO/deploy/cloudflare-vulnradar.py"
else
  echo "skipped"
fi

step "verification"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
sleep 5
ssh_srv "docker compose -f $REMOTE/deploy/docker-compose.server.yml --env-file $REMOTE/deploy/.env.prod ps --format '{{.Service}} {{.State}} {{.Status}}'"
DOWN=$(ssh_srv "docker compose -f $REMOTE/deploy/docker-compose.server.yml --env-file $REMOTE/deploy/.env.prod ps --format '{{.Service}} {{.State}}' | grep -v running || true")
if [ -n "$DOWN" ]; then
  echo "services not running:" >&2
  echo "$DOWN" >&2
  exit 1
fi
ssh_srv "
  echo -n 'local /health      : '; curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8501/health
  echo -n 'local /            : '; curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8501/
  echo -n 'local /cve?cve_id  : '; curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8501/cve?cve_id=CVE-2021-44228'
  echo -n 'local /soc panel?  : '; curl -s http://127.0.0.1:8501/soc | grep -qc 'SOC MONITORING' && echo 'EXPOSED (bad)' || echo 'login (ok)'
  echo -n 'worker last log    : '; docker logs --tail 3 vulnradar-worker-1 2>&1 | tr '\n' ' ' | cut -c1-200; echo
"
sleep 3
# The Windows resolver can cache NXDOMAIN for a freshly created domain: force the edge IP.
IP=$(nslookup vulnradar.munalabs.eu 1.1.1.1 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '^1\.1\.1\.1$' | head -1 | tr -d '\r')
if [ -n "${IP:-}" ]; then RES=(--resolve "vulnradar.munalabs.eu:443:$IP"); else RES=(); fi
echo -n "public https       : "
curl -s -m 25 ${RES[@]+"${RES[@]}"} -A "$UA" -o /dev/null -w '%{http_code} %{content_type}\n' https://vulnradar.munalabs.eu/
echo -n "public /soc        : "
curl -s -m 25 ${RES[@]+"${RES[@]}"} -A "$UA" -o /dev/null -w '%{http_code}\n' https://vulnradar.munalabs.eu/soc
echo
echo "done. logs: ssh ... 'docker logs -f vulnradar-worker-1'"
