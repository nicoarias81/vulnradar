#!/usr/bin/env bash
# Deploy de VulnRadar a personal-1 (Hetzner CAX21, ARM64) vía Cloudflare Tunnel.
#
#   bash deploy/deploy.sh                   # deploy completo (exige tree limpio y deploy/ commiteado)
#   bash deploy/deploy.sh --from-worktree    # deploya el working tree actual (sin commitear)
#   bash deploy/deploy.sh --allow-dirty      # deploya HEAD aunque haya cambios sin commitear
#   bash deploy/deploy.sh --no-build         # sólo recreate (cambios de env, no de código)
#   bash deploy/deploy.sh --skip-cloudflare  # sin tocar ingress/DNS
#
# El código viaja por tar (el server NO es git repo). `data/` y `deploy/.env.prod` nunca se pisan.
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

# Con hora en cada paso: sin esto no se sabe qué tramo del deploy consume los
# ~2 min que el sitio pasa abajo.
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
# Contenedores de un compose anterior quedan como `<hash>_vulnradar-<svc>` y se
# quedan con el nombre del servicio: el `up` los reconoce, los deja en `created`
# y no arranca nada. Se borran antes de levantar.
ssh_srv "docker ps -a --format '{{.Names}}' | grep -E '^[0-9a-f]{12}_vulnradar-' | xargs -r docker rm -f 2>&1 | tail -5 || true"

step "base services (proxy, active slot untouched)"
# El dashboard activo NO se recrea acá: lo reemplaza el blue-green de abajo.
ssh_srv "cd $REMOTE && docker compose -f deploy/docker-compose.server.yml --env-file deploy/.env.prod up -d --no-deps proxy 2>&1 | tail -6"

step "blue-green (candidate in parallel, traffic untouched until it responds)"
# Construir ANTES de levantar: compilar dentro del up deja el contenedor abajo.
# ab.sh levanta el slot inactivo, espera su /health (hasta 4 min) y recién ahí
# mueve el tráfico con un reload atómico de Caddy; si el candidato no responde,
# el sitio sigue sirviendo desde el slot anterior.
if [ "$BUILD" -eq 1 ]; then
  ssh_srv "cd $REMOTE && docker compose -f deploy/docker-compose.server.yml build 2>&1 | tail -8"
fi
# El worker comparte la imagen con los slots pero no pasa por el blue-green:
# recrearlo antes del build lo dejaba con el código anterior recalculando y
# pisando los scores nuevos en cada ciclo. Va después del build, siempre.
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
# El resolver de Windows puede tener NXDOMAIN cacheado de un dominio recién creado: forzamos la IP del edge.
IP=$(nslookup vulnradar.munalabs.eu 1.1.1.1 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '^1\.1\.1\.1$' | head -1 | tr -d '\r')
if [ -n "${IP:-}" ]; then RES=(--resolve "vulnradar.munalabs.eu:443:$IP"); else RES=(); fi
echo -n "public https       : "
curl -s -m 25 ${RES[@]+"${RES[@]}"} -A "$UA" -o /dev/null -w '%{http_code} %{content_type}\n' https://vulnradar.munalabs.eu/
echo -n "public /soc        : "
curl -s -m 25 ${RES[@]+"${RES[@]}"} -A "$UA" -o /dev/null -w '%{http_code}\n' https://vulnradar.munalabs.eu/soc
echo
echo "done. logs: ssh ... 'docker logs -f vulnradar-worker-1'"
