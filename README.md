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
         Base de datos local (SQLite/Postgres)
              ↓
         Scoring Agent (fórmulas v2)
              ↓
         [Capa de Contexto opcional]  ← aquí entra el inventario de assets
              ↓
         API / Dashboard / Alertas
```

## Quick Start

```bash
# 1. Clonar y entrar
cd humo-vs-miedo

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Inicializar base de datos
python -m core.db_init

# 4. Primera sincronización (puede tardar)
python agents/sync_agent.py --full

# 5. Correr enriquecimiento + scoring
python agents/enrichment_agent.py
python agents/scoring_agent.py

# 6. Dashboard
streamlit run dashboard/app.py
```

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
├── core/
│   ├── scoring.py          # Fórmulas v2
│   ├── models.py
│   ├── normalizer.py
│   └── db.py
├── config/
│   └── sources.yaml
└── dashboard/
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
