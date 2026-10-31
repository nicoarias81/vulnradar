#!/usr/bin/env bash
# Bootstrap en el server (personal-1). Idempotente: no pisa nada existente.
# Corre EN el server:   ssh ... 'bash /opt/vulnradar/deploy/bootstrap-server.sh'
set -euo pipefail

APP=/opt/vulnradar
ENV_PROD="$APP/deploy/.env.prod"
PANOPTICON_ENV=/opt/panopticon/deploy/.env.prod

mkdir -p "$APP/data"

# El upstream activo es estado del server, no del repo: el tar no lo trae y el
# proxy lo monta como archivo. Si falta (primer arranque), apuntar al slot a.
if [ ! -f "$APP/deploy/upstream.caddy" ]; then
  printf 'reverse_proxy dashboard-a:8501\n' > "$APP/deploy/upstream.caddy"
  echo "upstream.caddy: creado (dashboard-a)"
fi

if [ -f "$ENV_PROD" ]; then
  echo "env.prod: ya existe (no se toca)"
else
  SOC_PASSWORD="$(openssl rand -hex 16)"

  # Virtual key del LiteLLM compartido: se copia server-side, nunca se imprime.
  LITELLM_KEY=""
  if [ -f "$PANOPTICON_ENV" ]; then
    LITELLM_KEY="$(awk -F= '/^AI_API_KEY=/{sub(/^AI_API_KEY=/,""); print; exit}' "$PANOPTICON_ENV" | tr -d '\r')"
  fi

  umask 077
  {
    echo "# generado por deploy/bootstrap-server.sh"
    echo "SOC_USER=soc"
    echo "SOC_PASSWORD=$SOC_PASSWORD"
    echo "LLM_PROVIDER=litellm"
    echo "LLM_MODEL=qwen3.8-flash"
    echo "LITELLM_API_KEY=$LITELLM_KEY"
    echo "SYNC_INTERVAL_MINUTES=15"
    echo "GITHUB_TOKEN="
    echo "SLACK_WEBHOOK_URL="
    echo "ALERT_WEBHOOK_URL="
    echo "TZ=Europe/Madrid"
    echo "# PostgreSQL externo (obligatorio). Completar antes del primer up."
    echo "DATABASE_URL="
  } > "$ENV_PROD"
  chmod 600 "$ENV_PROD"
  echo "env.prod: creado (SOC_PASSWORD aleatorio, LITELLM_API_KEY: $([ -n "$LITELLM_KEY" ] && echo copiada || echo VACIA))"
fi

chmod 700 "$APP/deploy" 2>/dev/null || true
chmod 600 "$ENV_PROD"

if ! grep -q '^DATABASE_URL=.\+' "$ENV_PROD"; then
  echo "AVISO: DATABASE_URL vacío — el dashboard no arranca sin PostgreSQL externo"
fi

echo "data: $(du -sh "$APP/data" 2>/dev/null | cut -f1 || echo vacio)"
echo "disco libre: $(df -h / | awk 'NR==2{print $4}')"
echo "puerto 8501: $(ss -ltn | grep -c ':8501 ' || true) listener(s) previos"
