#!/usr/bin/env bash
# Blue-green: el proxy (Caddy) publica el puerto público y enruta al slot
# activo. Un deploy levanta el slot inactivo, espera su /health y recién ahí
# mueve el tráfico; si el candidato no responde, el tráfico no se toca.
#
# Uso:  scripts/ab.sh {up|deploy|status|rollback|logs}
#   COMPOSE_FILE  compose a usar (default: docker-compose.local.yml)
#   PROXY_PORT    puerto público del proxy (default: 8500 local / 8501 prod)
#   STATE_FILE    archivo con el slot activo (default: .ab-active)
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.local.yml}"
COMPOSE=(docker compose -f "$COMPOSE_FILE")
# En prod el compose espera deploy/.env.prod para interpolar y para el env_file.
[[ -n "${ENV_FILE:-}" ]] && COMPOSE+=(--env-file "$ENV_FILE")
STATE_FILE="${STATE_FILE:-.ab-active}"
PROXY_PORT="${PROXY_PORT:-8500}"
PROXY_SVC="${PROXY_SVC:-proxy}"
UPSTREAM_FILE="${UPSTREAM_FILE:-deploy/upstream.caddy}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-240}"

active() { [[ -f $STATE_FILE ]] && cat "$STATE_FILE" || echo a; }
other() { [[ $(active) == a ]] && echo b || echo a; }

health() { # $1=url
  # curl puede imprimir el código y salir distinto de 0 (p.ej. con -o /dev/null
  # en git-bash); capturar y validar evita que el fallback se concatene (200000).
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$1" 2>/dev/null) || true
  [[ $code =~ ^[0-9]{3}$ ]] || code=000
  echo "$code"
}

public_health() { health "http://localhost:${PROXY_PORT}/health"; }

wait_health() { # $1=url  $2=segundos
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
  # El proxy monta upstream.caddy como *archivo*: si algo lo reemplazó en el
  # host (tar del deploy, checkout), el contenedor sigue viendo el inodo viejo
  # y el reload lee el upstream anterior. Si lo que ve no es lo pedido, recrear.
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
      # El proxy ya apunta al candidato: confirmar desde el puerto público.
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
