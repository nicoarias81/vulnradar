#!/usr/bin/env bash
# Blue-green local. The active slot publishes on 8501; the candidate lives on 8502.
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f docker-compose.local.yml)
STATE=.ab-active

active() { [[ -f $STATE ]] && cat $STATE || echo a; }
port_of() { [[ $1 == a ]] && echo 8501 || echo 8502; }

health() {
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "http://localhost:$1/health" 2>/dev/null) || true
  printf '%s' "${code:-000}"
}

wait_health() { # $1=port  $2=seconds
  local end=$((SECONDS + $2))
  while (( SECONDS < end )); do
    [[ $(health "$1") == 200 ]] && return 0
    sleep 3
  done
  return 1
}

case "${1:-status}" in
  up)
    "${COMPOSE[@]}" up -d --build postgres dashboard-a
    wait_health 8501 200 || { echo "slot a did not come up"; exit 1; }
    echo a > $STATE
    echo "active: a (8501)  ·  postgres: 5433"
    ;;
  deploy)
    cur=$(active)
    cand=$([[ $cur == a ]] && echo b || echo a)
    cand_port=$(port_of "$cand")
    "${COMPOSE[@]}" build "dashboard-$cand"
    "${COMPOSE[@]}" up -d "dashboard-$cand"
    if wait_health "$cand_port" 200; then
      echo "$cand" > $STATE
      echo "promoted: $cand ($cand_port). slot $cur stays up for rollback"
    else
      echo "candidate $cand failed the healthcheck; $cur stays active"
      "${COMPOSE[@]}" logs --tail 30 "dashboard-$cand"
      exit 1
    fi
    ;;
  switch)
    cur=$(active)
    other=$([[ $cur == a ]] && echo b || echo a)
    other_port=$(port_of "$other")
    wait_health "$other_port" 30 || { echo "slot $other is not up"; exit 1; }
    echo "$other" > $STATE
    echo "active now: $other ($other_port)"
    ;;
  status)
    cur=$(active)
    echo "active: $cur ($(port_of "$cur"))   candidate: $([[ $cur == a ]] && echo b || echo a)"
    printf '  a 8501: %s   b 8502: %s   pg 5433: %s\n' \
      "$(health 8501)" "$(health 8502)" \
      "$(docker exec vulnradar-pg-local pg_isready -U vuln 2>/dev/null | grep -c accepting || true)"
    ;;
  down)
    "${COMPOSE[@]}" down
    ;;
  *)
    echo "usage: $0 {up|deploy|switch|status|down}"; exit 2 ;;
esac
