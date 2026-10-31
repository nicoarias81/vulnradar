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
STATE_FILE="${STATE_FILE:-.ab-active}"
PROXY_PORT="${PROXY_PORT:-8500}"
PROXY_SVC="${PROXY_SVC:-proxy}"
UPSTREAM_FILE="${UPSTREAM_FILE:-deploy/upstream.caddy}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-240}"

active() { [[ -f $STATE_FILE ]] && cat "$STATE_FILE" || echo a; }
other() { [[ $(active) == a ]] && echo b || echo a; }

health() { # $1=url
  curl -s -o /dev/null -w '%{http_code}' -m 10 "$1" 2>/dev/null || echo 000
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
  printf 'reverse_proxy dashboard-%s:8501\n' "$1" > "$UPSTREAM_FILE"
  "${COMPOSE[@]}" exec -T "$PROXY_SVC" caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1 \
    || { echo "reload del proxy falló"; return 1; }
}

case "${1:-status}" in
  up)
    "${COMPOSE[@]}" up -d --build postgres dashboard-a "$PROXY_SVC"
    wait_health "$(slot_url a)" "$HEALTH_TIMEOUT" || { echo "slot a no levantó"; exit 1; }
    echo a > "$STATE_FILE"
    set_upstream a
    echo "activo: a · público: ${PROXY_PORT} · postgres local"
    ;;
  deploy)
    cur=$(active); cand=$(other)
    echo "activo=$cur · construyendo candidato=$cand"
    "${COMPOSE[@]}" build "dashboard-$cand"
    "${COMPOSE[@]}" up -d --no-deps "dashboard-$cand"
    if wait_health "$(slot_url "$cand")" "$HEALTH_TIMEOUT"; then
      set_upstream "$cand"
      # El proxy ya apunta al candidato: confirmar desde el puerto público.
      if [[ $(public_health) == 200 ]]; then
        echo "$cand" > "$STATE_FILE"
        echo "promovido: $cand · tráfico movido · $cur queda arriba para rollback"
      else
        set_upstream "$cur"
        echo "el público no respondió con $cand: rollback automático a $cur"; exit 1
      fi
    else
      echo "candidato $cand no pasó health en ${HEALTH_TIMEOUT}s; tráfico intacto en $cur"
      "${COMPOSE[@]}" logs --tail 30 "dashboard-$cand" || true
      exit 1
    fi
    ;;
  rollback)
    cur=$(active); back=$(other)
    wait_health "$(slot_url "$back")" 30 || { echo "slot $back no está arriba; no hay a dónde volver"; exit 1; }
    set_upstream "$back"
    echo "$back" > "$STATE_FILE"
    echo "rollback: activo $back"
    ;;
  status)
    echo "activo: $(active) · público ${PROXY_PORT}: $(public_health)"
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
