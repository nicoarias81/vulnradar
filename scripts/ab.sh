#!/usr/bin/env bash
# Blue-green: the proxy (Caddy) exposes the public port and routes to the
# active slot. A deploy brings up the inactive slot, waits for its /health and only then
# moves traffic; if the candidate does not answer, traffic is not touched.
#
# Usage:  scripts/ab.sh {up|deploy|status|rollback|logs}
#   COMPOSE_FILE  compose file to use (default: docker-compose.local.yml)
#   PROXY_PORT    public proxy port (default: 8500 local / 8501 prod)
#   STATE_FILE    file holding the active slot (default: .ab-active)
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.local.yml}"
COMPOSE=(docker compose -f "$COMPOSE_FILE")
# In prod the compose file expects deploy/.env.prod to interpolate and for env_file.
[[ -n "${ENV_FILE:-}" ]] && COMPOSE+=(--env-file "$ENV_FILE")
STATE_FILE="${STATE_FILE:-.ab-active}"
PROXY_PORT="${PROXY_PORT:-8500}"
PROXY_SVC="${PROXY_SVC:-proxy}"
UPSTREAM_FILE="${UPSTREAM_FILE:-deploy/upstream.caddy}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-240}"

active() { [[ -f $STATE_FILE ]] && cat "$STATE_FILE" || echo a; }
other() { [[ $(active) == a ]] && echo b || echo a; }

health() { # $1=url
  # curl can print the code and exit non-zero (e.g. with -o /dev/null
  # on git-bash); capturing and validating avoids the fallback being concatenated (200000).
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$1" 2>/dev/null) || true
  [[ $code =~ ^[0-9]{3}$ ]] || code=000
  echo "$code"
}

public_health() { health "http://localhost:${PROXY_PORT}/health"; }

wait_health() { # $1=url  $2=seconds
  local end=$((SECONDS + $2))
  while (( SECONDS < end )); do
    [[ $(health "$1") == 200 ]] && return 0
    sleep 3
  done
  return 1
}

slot_url() { echo "http://localhost:$( [[ $1 == a ]] && echo "${SLOT_A_PORT:-8511}" || echo "${SLOT_B_PORT:-8512}")/health"; }

set_upstream() { # $1=slot
  local want seen
  want="reverse_proxy dashboard-$1:8501"
  printf '%s\n' "$want" > "$UPSTREAM_FILE"
  # The proxy mounts upstream.caddy as a *file*: if something replaced it on the
  # host (deploy tar, checkout), the container still sees the old inode
  # and the reload reads the previous upstream. If what it sees is not the requested one, recreate.
  seen=$("${COMPOSE[@]}" exec -T "$PROXY_SVC" cat /etc/caddy/upstream.caddy 2>/dev/null | tr -d '\r' | head -n1)
  if [[ $seen != "$want" ]]; then
    "${COMPOSE[@]}" up -d --no-deps --force-recreate "$PROXY_SVC" >/dev/null 2>&1
    sleep 2
  fi
  "${COMPOSE[@]}" exec -T "$PROXY_SVC" caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1 \
    || { echo "proxy reload failed"; return 1; }
}

case "${1:-status}" in
  up)
    "${COMPOSE[@]}" up -d --build postgres dashboard-a "$PROXY_SVC"
    wait_health "$(slot_url a)" "$HEALTH_TIMEOUT" || { echo "slot a did not come up"; exit 1; }
    echo a > "$STATE_FILE"
    set_upstream a
    echo "active: a · public: ${PROXY_PORT} · local postgres"
    ;;
  deploy)
    cur=$(active); cand=$(other)
    echo "active=$cur · building candidate=$cand"
    "${COMPOSE[@]}" build "dashboard-$cand"
    "${COMPOSE[@]}" up -d --no-deps "dashboard-$cand"
    if wait_health "$(slot_url "$cand")" "$HEALTH_TIMEOUT"; then
      set_upstream "$cand"
      # The proxy already points at the candidate: confirm from the public port.
      if [[ $(public_health) == 200 ]]; then
        echo "$cand" > "$STATE_FILE"
        echo "promoted: $cand · traffic moved · $cur stays up for rollback"
      else
        set_upstream "$cur"
        echo "public did not answer from $cand: automatic rollback to $cur"; exit 1
      fi
    else
      echo "candidate $cand failed health in ${HEALTH_TIMEOUT}s; traffic untouched on $cur"
      "${COMPOSE[@]}" logs --tail 30 "dashboard-$cand" || true
      exit 1
    fi
    ;;
  rollback)
    cur=$(active); back=$(other)
    wait_health "$(slot_url "$back")" 30 || { echo "slot $back is not up; nowhere to fall back to"; exit 1; }
    set_upstream "$back"
    echo "$back" > "$STATE_FILE"
    echo "rollback: activo $back"
    ;;
  status)
    echo "active: $(active) · public ${PROXY_PORT}: $(public_health)"
    printf '  slot a %s: %s\n  slot b %s: %s\n' \
      "${SLOT_A_PORT:-8511}" "$(health "$(slot_url a)")" \
      "${SLOT_B_PORT:-8512}" "$(health "$(slot_url b)")"
    ;;
  logs)
    "${COMPOSE[@]}" logs --tail 40 "dashboard-$(active)"
    ;;
  *)
    echo "uso: $0 {up|deploy|status|rollback|logs}"; exit 2 ;;
esac
