# Deploy de VulnRadar (público) — personal-1

`https://vulnradar.munalabs.eu` — sitio **público**, servido por Cloudflare Tunnel, sin puertos abiertos.

```
Internet → Cloudflare edge → tunnel "personal-1" → http://localhost:8501 → contenedor vulnradar-dashboard-1
                                                                        ↘ contenedor vulnradar-worker-1 (sync→enrich→score→alert)
```

| | |
|---|---|
| Server | Hetzner CAX21 ARM64, `ssh.munalabs.eu` (sólo por túnel) |
| Código | `/opt/vulnradar` (no es git repo: se sincroniza con `git archive HEAD`) |
| Datos | `/opt/vulnradar/data` (bind mount): mirror `cvelistV5`. DB = PostgreSQL externo (`DATABASE_URL`) |
| Secretos | `/opt/vulnradar/deploy/.env.prod` (chmod 600, generado en el server, nunca en el repo) |
| Puerto | `127.0.0.1:8501` — nada escucha en 0.0.0.0 |
| Redes | `default` (egress: git/CISA/EPSS/RSS/GitHub) + `internal` (LiteLLM compartido de `/opt/stack`) |
| LLM | `LLM_BASE_URL=http://litellm:4000/v1`, modelo `qwen3.8-flash`, key = virtual key del LiteLLM |
| Panel SOC | `/soc` con `SOC_USER`/`SOC_PASSWORD` (cookie HMAC). Sin password el panel queda cerrado |
| Access | **sin** Cloudflare Access: el sitio es público a propósito |

## Deploy (cuando el código esté listo)

```bash
bash deploy/deploy.sh            # exige tree limpio; aborta si no
```

Hace, en orden: preflight (git limpio + SSH + disco) → `git archive HEAD` al server → normaliza CRLF →
bootstrap (`/opt/vulnradar/data`, `.env.prod` si falta) → chequeos de env sin imprimir valores →
`docker compose up -d --build` → ingress + DNS en Cloudflare → verificación (local y pública).

Flags: `--from-worktree` (deploya el working tree sin commitear), `--allow-dirty` (deploya HEAD aunque haya
cambios sin commitear), `--no-build` (sólo recreate por cambio de env), `--skip-cloudflare`.

> Ojo: `git archive HEAD` **no** incluye archivos untracked. Si `deploy/` no está commiteado, el script
> aborta y pide commitear o usar `--from-worktree`.

## Estado al preparar este runbook (verificado)

- `/opt/vulnradar` existe con el código + `deploy/`; `/opt/vulnradar/data` vacío (4 KB).
- `deploy/.env.prod` creado, `chmod 600`, `SOC_PASSWORD` de 32 hex aleatorio, `LITELLM_API_KEY` copiada
  server-side desde `/opt/panopticon/deploy/.env.prod` (hash coincide; esa key ya responde 200 con
  `qwen3.8-flash` en `litellm:4000`).
- `docker compose -f deploy/docker-compose.server.yml --env-file deploy/.env.prod config --quiet` → válido.
- Ingress + DNS **creados** (`vulnradar.munalabs.eu` → `http://localhost:8501`, CNAME proxied al túnel,
  catch-all intacto, sin Access app). Backup previo del ingress: `/root/cf-backups/tunnel-ingress-*.json`.
- **Deployado y en producción** (dashboard healthy, worker con ciclos completos, sitio público 200).

### Notas de verificación desde esta máquina

- El resolver de Windows puede quedar con NXDOMAIN cacheado del dominio recién creado: `curl` normal da
  000 aunque `nslookup` contra 1.1.1.1 resuelva. Usar `--resolve vulnradar.munalabs.eu:443:<IP edge>`
  (el `deploy.sh` ya lo hace) o flushear DNS en una consola elevada.
- Desde el server, `curl https://*.munalabs.eu` devuelve 403 (filtro de Cloudflare a IPs de datacenter:
  pasa igual con `hermes.munalabs.eu`). No sirve como prueba de disponibilidad; verificar desde otra red.

## Pasos por separado

```bash
# 1. código (sin tocar data/ ni .env.prod)
git archive --format=tar HEAD | ssh ... 'tar -x -C /opt/vulnradar'

# 2. dirs + env.prod (idempotente)
ssh ... 'bash /opt/vulnradar/deploy/bootstrap-server.sh'

# 3. build + up
ssh ... 'cd /opt/vulnradar && docker compose -f deploy/docker-compose.server.yml --env-file deploy/.env.prod up -d --build'

# 4. ingress + DNS (público: sin app de Access)
ssh ... 'set -a; source /opt/cloudflare/credentials.env; set +a; python3 -' < deploy/cloudflare-vulnradar.py
```

## Verificación

```bash
ssh ... "curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8501/health"        # 200
ssh ... "curl -s http://127.0.0.1:8501/soc | grep -c 'SOC MONITORING'"                  # 0 (login)
curl -s -A "Mozilla/5.0" -o /dev/null -w '%{http_code}\n' https://vulnradar.munalabs.eu/  # 200
ssh ... 'docker logs --tail 30 vulnradar-worker-1'
```

Esperado en `/soc` sin cookie: página de login (200). Con cookie: panel `SOC MONITORING`.

## Primer arranque (importante)

`SEED_DEMO=0`: la DB arranca vacía y **el worker la llena solo**. El primer ciclo es caro:

1. `git clone --depth 1` del mirror cvelistV5 (~1–2 GB en disco).
2. Recorrido completo de ~395k archivos JSON → PostgreSQL.
3. Enrichment por ciclo: KEV + EPSS completos, RSS, PoC de 25 CVEs, tone de 50 CVEs (lotes de 10).
4. Scoring sobre los CVEs enriquecidos.

O sea: el sitio público arranca mostrando poco y se va poblando. Un ciclo puede durar más que
`SYNC_INTERVAL_MINUTES=15`; el loop simplemente duerme al terminar. Seguimiento:

```bash
ssh ... 'docker logs -f --tail 50 vulnradar-worker-1'
ssh ... "docker exec vulnradar-dashboard-1 python -c \"from core.db import get_db;c=get_db();print([(t,c.execute('select count(*) from '+t).fetchone()[0]) for t in ('cves','scores','enrichments')]);c.close()\""
```

## Operación

```bash
# logs
ssh ... 'docker logs -f --tail 100 vulnradar-dashboard-1'
# backup PostgreSQL (pg_dump) + rotación (cron sugerido 04:00)
ssh ... 'bash /opt/vulnradar/deploy/backup-db.sh'
# credenciales del panel SOC
ssh ... 'grep -E "^SOC_(USER|PASSWORD)=" /opt/vulnradar/deploy/.env.prod'
# rollback de código a un commit anterior
git archive --format=tar <sha> | ssh ... 'tar -x -C /opt/vulnradar'   # + up -d --build
# apagar
ssh ... 'cd /opt/vulnradar && docker compose -f deploy/docker-compose.server.yml down'
```

## Notas de seguridad

- `.dockerignore` excluye `.env*` y `deploy/`: la imagen **no** lleva `.env.prod` (verificado con marcador).
- El código escapa con `html.escape()` todo lo que viene de la DB (títulos RSS, descripciones CVE).
- Lo único con escritura es `POST /soc` (login); el resto es sólo lectura.
- Los contenedores corren como root dentro de la imagen (default); sin puertos publicados más allá de 127.0.0.1.

## Pendientes/decisiones al momento de este runbook

- Confirmar el alcance público: hoy cualquiera puede leer `/`, `/cve`, `/agentes`; `/soc` pide password.
- Smoke del LLM en prod (que la virtual key habilite `qwen3.8-flash`); si no, el tone cae a heurística.
- El overview necesita CVEs **puntuados**; hasta que el worker complete ciclos, la portada se ve vacía.
