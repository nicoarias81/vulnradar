# Arquitectura — Humo vs Miedo

## Principios de diseño

1. **Capas desacopladas**: cada capa solo conoce el esquema normalizado.
2. **Extensible**: nuevas fuentes o la capa de Contexto se agregan sin tocar el core.
3. **Reproducible**: el scoring es determinista y auditable.
4. **Agentes**: cada responsabilidad es un proceso independiente.

## Capas

### 1. Ingestión
- Sync Agent: git pull de CVE List V5 + delta
- Enrichment Agent: KEV, EPSS, RSS, GitHub PoCs

### 2. Normalización
Esquema interno único:

```json
{
  "cve_id": "CVE-2026-XXXXX",
  "published": "2026-...",
  "cvss": 9.8,
  "signals": {
    "in_kev": true,
    "epss": 0.87,
    "media_count": 12,
    "poc_count": 5,
    "tone_score": 8.0,
    "branding": true
  }
}
```

### 3. Scoring
Aplica fórmulas v2. Genera Hype, Reality y categoría.

### 4. Contexto de assets (opcional)
- Inventario de assets
- Criticidad por asset
- Ajuste del score final
- Mapeo CVE → assets afectados

### 5. Salida
- API REST
- Dashboard (Streamlit)
- Alertas (Slack, webhook, email)

### Worker autónomo
`scripts/run_worker.py` (servicio `worker` en Compose) corre en loop:
sync incremental → enrich → score → alert. Intervalo: `SYNC_INTERVAL_MINUTES`
(default 15). Un paso que falla no cancela los siguientes. El dashboard de
Agentes lee `agent_events`. No requiere comandos manuales.

## Flujo de datos

```
CVE List V5 ──┐
CISA KEV     ──┤
EPSS         ──┼→ Enrichment → DB local → Scoring → [Contexto] → Dashboard/Alerts
RSS + GitHub ──┘
```

## Extensión futura

- Nuevas fuentes: añadir un feeder en Enrichment Agent
- Contexto de assets: implementar `core/context.py` y llamar después del scoring
- Nuevos canales de alerta: añadir en Alert Agent
