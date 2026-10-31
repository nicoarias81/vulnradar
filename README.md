# VulnRadar

**Sistema open source de scoring dual (Hype vs Reality) para CVEs, diseñado para agentes y extensible.**

<a href="https://nan.builders/?ref=built-with-nan">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://nan.builders/badge/built-with-nan-light.svg">
    <img width="266" src="https://nan.builders/badge/built-with-nan-dark.svg" alt="Built with NaN">
  </picture>
</a>

**Demo:** https://vulnradar.munalabs.eu · **Repo:** https://github.com/nicoarias81/vulnradar

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
coloreado por categoría, tabla **Pay attention to**, tabla de CVEs recientes,
timeline compacta de Score evolution y ficha de detalle. Lo sirve
`python scripts/run_dashboard.py` (o `make dashboard`) en el puerto 8501.

La portada entra en una pantalla sin scrollear: a la izquierda el scatter con la
timeline como franja al pie, a la derecha **Pay attention to** arriba y **Recent
CVEs** abajo. **Pay attention to** filtra por *evidencia de explotación*, no por
CVSS: entra un CVE con KEV, con EPSS ≥ 0.70 o con al menos un PoC público, y el
orden es KEV → EPSS → PoC. Cada fila muestra las señales como badges (KEV con
fecha de alta, cantidad de PoC, EPSS) y un medidor de Reality. La tabla de
recientes sigue siendo cronológica, de más nuevo a más viejo.

La timeline estira el eje solo según el máximo del período. En la portada va en
modo compacto (sin destacados ni eje de valores, tres fechas de referencia); el
detalle de cada CVE conserva la versión completa con hover por día (fecha, CVEs,
Hype, Reality y CVE top) y hasta 3 **destacados** con guía vertical y chip; esos
scores son los del CVE, no el promedio diario del eje. La portada se recarga
cada 60 s sin contar como visita.

El panel **SOC monitoring** (estado de los 4 agentes, feed y logs) vive en
http://localhost:8501/soc y **no es público**. Pide `SOC_USER` / `SOC_PASSWORD`
del `.env`. Sin `SOC_PASSWORD` el login queda cerrado. `Salir` borra la cookie.
La pantalla pública no enlaza al SOC.

Con la base vacía la página no rompe: el worker autónomo llena scores en el
próximo ciclo; con `SEED_DEMO=1` hay 8 CVEs de ejemplo. La carga y el filtrado
`dashboard/data.py` y se testean con `pytest`. La home no materializa
el histórico: `COUNT(*)` para el total y para los accionables, scatter `LIMIT 400`
(prioriza branding y hype), accionables `LIMIT 6` ordenados por evidencia, tabla
paginada (`LIMIT/OFFSET`, 6 u 100 en View all) y timeline con `GROUP BY` diario.
El panel SOC se refresca solo con los eventos de `agent_events`.

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

Las menciones entran por dos caminos. El ciclo procesa los feeds del día y,
aparte, prioriza un lote de CVEs (KEV, con PoC, recientes) y busca cada uno en
Hacker News vía Algolia: es lo que recupera prensa de un CVE que ya salió de
los feeds. Si un CVE aparece en los dos, la URL dedupe.

`config/sources.yaml` separa dos clases de feed. Los de prensa y research pasan
por el LLM, que descarta lo que no es una vulnerabilidad concreta y resuelve el
CVE del texto. Los advisories de vendors y CERT (`rss_regex_only`) ya traen el
CVE en el titular, así que van por regex, sin modelo: 10 feeds de ese tipo
aportan ~600 CVEs en 11 segundos.

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
`Overhyped`, `Earned the hype`, `Sleeper` y **hype sin sustento** (`tone_score >= 7` con
`reality < 5`, ajustable con `--humo-tone`/`--humo-reality`).

Canales por entorno: `SLACK_WEBHOOK_URL` (incoming webhook, `{text, blocks}`) y
`ALERT_WEBHOOK_URL` (JSON plano, `event: vulnradar.alert`); sin URL, ese canal
se omite. `alerts_sent`
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
vulnradar/
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
    ├── markup.py           # HTML de portada, ficha y panel SOC
    ├── server.py           # servidor HTTP en 8501
    ├── theme.py            # tokens y componentes visuales
    └── app.py              # vista Streamlit (alternativa)
```

## Scoring v2 (resumen)

**Reality**  
`0.45*KEV + 0.25*(EPSS*10) + 0.20*Wild + 0.05*Ransomware + 0.05*Complexity`

**Hype**  
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
| RSS seguridad | Cobertura mediática | 25 feeds: THN, BleepingComputer, Talos, Unit 42, Project Zero, watchTowr, etc. |
| Advisories vendor/CERT | CVE explícito, sin LLM | MSRC, Cisco PSIRT, ZDI, Palo Alto, Ivanti, Fortinet, CERT-FR, INCIBE, CERT-EU, Exploit-DB |
| Hacker News (Algolia) | Prensa de CVEs fuera de los feeds | https://hn.algolia.com/api |
| GitHub Search | PoCs | API pública |

## Ambiente local con A/B

`docker-compose.local.yml` levanta un PostgreSQL propio (puerto 5433) y dos
slots del dashboard contra la misma base: `a` en 8501 y `b` en 8502. Cambiar de
slot no migra datos, así que el candidato se puede probar completo antes de
mover el tráfico.

    ./scripts/local_ab.sh up       # postgres + slot a, activo en 8501
    ./scripts/local_ab.sh deploy   # buildea el slot inactivo, espera /health y lo promueve
    ./scripts/local_ab.sh switch   # vuelve al otro slot (rollback)
    ./scripts/local_ab.sh status   # qué slot está activo y si los tres puertos responden

El slot activo queda en `.ab-active`, que no se versiona. En Windows con Docker
Desktop hay que consultar `localhost` y no `127.0.0.1`: el puerto se publica en
IPv6 y la IP de loopback devuelve "empty reply".

## Licencia

MIT.
