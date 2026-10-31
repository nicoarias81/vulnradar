# Humo vs Miedo

**Sistema open source de scoring dual (Hype vs Reality) para CVEs, diseñado para agentes y extensible.**

Versión base open source. La capa de contexto (inventario de assets + criticidad) es opcional y se enchufa sin modificar el core.

## Características

- **Mirror interno** de CVE List V5 (GitHub) + sincronización incremental
- Scoring dual transparente y reproducible (fórmulas v2)
- Arquitectura por capas: Ingestión → Normalización → Scoring → Contexto → Salida
- Agentes desacoplados (Sync, Enrichment, Scoring, Alert)
- 100% fuentes abiertas (CVE List V5, CISA KEV, FIRST EPSS, RSS, GitHub)
- Extensible: la capa de Contexto es un plugin

## Arquitectura

```
[CVE List V5 / KEV / EPSS / RSS / GitHub]
              ↓
         Sync Agent + Enrichment Agent
              ↓
         PostgreSQL externo
              ↓
         Scoring Agent (fórmulas v2)
              ↓
         [Capa de Contexto opcional]  ← aquí entra el inventario de assets
              ↓
         API / Dashboard / Alertas
```

## Quick Start

El sistema es autónomo: un worker en loop hace sync → enrich → score → alert.
No hace falta entrar a correr agentes a mano.

```bash
cp .env.example .env   # DATABASE_URL, LITELLM_API_KEY, webhooks, opcional GITHUB_TOKEN
docker compose up --build -d
# Dashboard: http://localhost:8501
docker compose logs -f worker
```

`docker compose up --build -d` levanta **dashboard + worker**. El worker corre
solo, en loop (`SYNC_INTERVAL_MINUTES`, default 15):

1. `git fetch --depth 1` + merge ff-only del mirror CVE List V5 (clone `--depth 1` si no existe; si origin reescribió historia, `reset --hard` al tip remoto)
2. sync incremental a PostgreSQL
3. enrichment (KEV, EPSS, RSS, GitHub, LLM)
4. scoring
5. alertas (si hay webhook configurado)

La UI queda en http://localhost:8501 (seed de 8 CVEs para no arrancar vacío;
el worker va sumando CVEs reales).

```bash
docker compose down
```

### One-shot local (sin Docker)

```bash
pip install -r requirements.txt
python -m core.db
python scripts/run_worker.py          # loop autónomo
# o un ciclo: python scripts/run_worker.py --once
streamlit run dashboard/app.py
```

Los `make sync` / `make enrich` / `make score` siguen existiendo para debug.

## Dashboard

El tablero **público** está en http://localhost:8501: scatter **Hype vs Reality**
coloreado por categoría, tabla de CVEs y ficha de detalle. Lo sirve
`python scripts/run_dashboard.py` (o `make dashboard`) en el puerto 8501.

El panel **SOC monitoring** (estado de los 4 agentes, feed y logs) vive en
http://localhost:8501/soc y **no es público**. Pide `SOC_USER` / `SOC_PASSWORD`
del `.env`. Sin `SOC_PASSWORD` el login queda cerrado. `Salir` borra la cookie.
La pantalla pública no enlaza al SOC.

Con la base vacía la página no rompe: el worker autónomo llena scores en el
próximo ciclo; con `SEED_DEMO=1` hay 8 CVEs de ejemplo. La carga y el filtrado
viven en `dashboard/data.py` y se testean con `pytest`. La home no materializa
el histórico: `COUNT(*)` para el total, scatter `LIMIT 400` (prioriza branding
y hype), tabla paginada (`LIMIT/OFFSET`, 6 u 100 en View all) y timeline con
`GROUP BY` diario. El panel SOC se refresca solo con los eventos de `agent_events`.

## Sync incremental

El sync incremental es el modo por defecto: lo que se corre a diario.

```bash
python agents/sync_agent.py            # incremental (default)
python agents/sync_agent.py --full     # recorre todo el mirror
make sync-delta                        # incremental
make sync                              # --full
```

El watermark es el **SHA de HEAD del mirror git local** (`sync_state.cvelist_head`),
no `dateUpdated`: un CVE se puede republicar sin mover su fecha, y un archivo
puede cambiar por una corrección de metadatos. En cada corrida incremental:

1. `git fetch --depth 1` + `merge --ff-only` sobre el mirror (el diff se
   calcula **antes** del merge: en un clone shallow el commit viejo puede
   desaparecer después). Si origin reescribió `main`, `reset --hard FETCH_HEAD`.
2. Si no hay watermark y el pull trajo un delta: sólo esos archivos.
3. Si no hay watermark y la DB ya tiene CVEs: se adopta el HEAD actual,
   sin re-escanear el árbol (reinicio del worker).
4. Si no hay watermark y la DB está vacía (primera vez): recorrido completo.
5. Si el HEAD no cambió: 0 archivos, watermark igual, exit 0.
6. Si cambió: `git diff --name-only OLD NEW` y se procesan sólo los
   `cves/**/*.json` añadidos o modificados. Los borrados se ignoran (no se
   borran filas locales).
7. Si el SHA viejo ya no existe en el mirror (re-clone, historia reescrita),
   se degrada a recorrido completo en lugar de fallar.
8. Al terminar se guarda el HEAD actual en `sync_state`.

Para tests se puede inyectar el mirror y la base:
`sync(full=False, cve_list_path="...", db_path="...")` o `--cve-list-path`/
`--db-path` por CLI (`db_path` aísla un schema de test; producción usa `DATABASE_URL`).

## Enriquecimiento

`python agents/enrichment_agent.py` corre cinco señales por CVE: CISA KEV,
EPSS, menciones de prensa (RSS de `config/sources.yaml`), PoCs en GitHub y
`tone_score`/branding. Cada fuente escribe **sólo sus columnas**, así que KEV,
EPSS, media, PoCs y tone conviven en la misma fila de `enrichments`.

El RSS deduplica por URL en `media_mentions` (una URL nueva suma 1 a
`media_count`); los PoCs **reemplazan** `poc_count`; y el tone/branding sale de
un lote de 10 titulares por llamada al LLM configurable (LiteLLM en
`config/llm.yaml` + `core/llm.py`), con fallback heurístico si el modelo no
responde o devuelve JSON roto.

Flags: `--skip-kev --skip-epss --skip-rss --skip-github --skip-llm`, más
`--rss-only` (prueba local) y `--llm-smoke` (una llamada real al proveedor).

## Alertas

`python agents/alert_agent.py` lee los scores vigentes (JOIN `cves` +
`enrichments`) y avisa por Slack y/o webhook genérico. Reglas opt-in:
`Overhyped`, `Earned the hype`, `Sleeper` y **humo** (`tone_score >= 7` con
`reality < 5`, ajustable con `--humo-tone`/`--humo-reality`).

Canales por entorno: `SLACK_WEBHOOK_URL` (incoming webhook, `{text, blocks}`) y
`ALERT_WEBHOOK_URL` (JSON plano); sin URL, ese canal se omite. `alerts_sent`
deduplica por `UNIQUE(cve_id, channel, rule)` y sólo se escribe **después** de
un POST exitoso: un 4xx/5xx deja la alerta pendiente para la próxima corrida.

```bash
make alerts-dry                      # evalúa e imprime: no POSTea ni escribe
python agents/alert_agent.py --once  # pasada real (make alerts)
```

## Tests

```bash
pytest -q
```

Los tests no usan red: el scoring, la normalización, los UPSERTs y el sync
incremental se prueban contra schemas PostgreSQL aislados (`DATABASE_URL` +
clave `tmp_path`) y un mini repo git armado en el propio tmp.

## Estructura del proyecto

```
humo-vs-miedo/
├── README.md
├── ARCHITECTURE.md
├── requirements.txt
├── docker-compose.yml
├── .env.example
├── schema.sql
├── agents/
│   ├── sync_agent.py
│   ├── enrichment_agent.py
│   ├── scoring_agent.py
│   └── alert_agent.py
├── scripts/
│   ├── run_dashboard.py
│   └── run_worker.py          # loop autónomo sync→enrich→score→alert
├── core/
│   ├── scoring.py          # Fórmulas v2
│   ├── models.py
│   ├── normalizer.py
│   └── db.py
├── config/
│   └── sources.yaml
├── tests/
│   ├── test_scoring.py
│   ├── test_normalizer.py
│   ├── test_db_upsert.py
│   ├── test_alerts.py
│   ├── test_sync_incremental.py
│   └── test_dashboard.py
└── dashboard/
    ├── data.py             # Load + filtros (sin Streamlit)
    └── app.py
```

## Scoring v2 (resumen)

**Reality (Miedo)**  
`0.45*KEV + 0.25*(EPSS*10) + 0.20*Wild + 0.05*Ransomware + 0.05*Complexity`

**Hype (Humo)**  
`0.20*CVSS + 0.30*Media + 0.15*Branding + 0.20*Tone + 0.15*PoCs`

Categorías: Overhyped, Earned the hype, Sleeper, Quiet.

## Extensión de contexto

La capa de **Contexto** se inyecta después del Scoring:

- Cargar inventario de assets (CSV, API, CMDB)
- Asignar criticidad (1-10) por asset
- Ajustar Reality final: `Reality_ajustado = Reality * (criticidad / 5.0)`
- Alertas a Slack cuando `CVE × asset_crítico` supera umbral

Ver `docs/EXTENSION_CONTEXT.md`.

## Fuentes abiertas utilizadas

| Fuente | Uso | URL |
|--------|-----|-----|
| CVE List V5 | Mirror principal | https://github.com/CVEProject/cvelistV5 |
| CISA KEV | Reality fuerte | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| FIRST EPSS | Probabilidad | https://epss.empiricalsecurity.com/epss_scores-current.csv.gz |
| RSS seguridad | Cobertura mediática | THN, BleepingComputer, etc. |
| GitHub Search | PoCs | API pública |

## Licencia

MIT.
