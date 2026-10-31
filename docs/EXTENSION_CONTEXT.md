# Extensión de Contexto

Esta capa es opcional: se activa cuando hay un inventario de assets propio.

## Objetivo

Ajustar el Reality de un CVE según la criticidad de los assets afectados.

## Modelo

1. Cargar inventario de assets (CSV, API, CMDB, ServiceNow, etc.)
2. Cada asset tiene `criticality` (1.0 – 10.0)
3. Mapear CVE → assets (por producto, CPE, o manual)
4. Calcular:
   ```
   Reality_ajustado = Reality_base * (criticality / 5.0)
   ```
5. Generar alertas cuando `Reality_ajustado > umbral` y el asset es crítico

## Ejemplo de uso

```python
# Con un inventario cargado
from core.context import apply_asset_context

base_scores = scoring_agent.run()
adjusted = apply_asset_context(base_scores, inventory)
alert_agent.notify(adjusted)
```

## Tabla de assets (ya incluida en schema.sql)

Ver `schema.sql` → tablas `assets` y `cve_assets`.
