# Scoring v4.1: especificación y límites

Implementación: `v4.1-evidence-tiers-attention-30d`. Fecha: 1 de noviembre de 2026.
Es un índice ordinal con reglas explícitas de seguridad. No es una probabilidad
calibrada ni calcula el riesgo de los activos de una organización.

## Reglas

| Estado | Criterio | Reality |
|---|---|---|
| Explotación confirmada | KEV o sighting de un autor CIRCL explícitamente confiable | `7 + ransomware + EPSS`, entre 7 y 9 |
| Evidencia predictiva | Sin confirmación confiable | `min(5.9, 5*EPSS + public_poc)` |
| Desconocido | EPSS ausente, inválido o con más de siete días, sin confirmación | Se muestra `Unknown`; el número no significa bajo riesgo |

`ransomware` y `public_poc` valen 0 o 1. EPSS conserva su valor original 0–1,
fecha y versión de modelo. Un PoC público procede de Exploit-DB o de artefactos
expresamente validados; las coincidencias de GitHub son candidatos, no prueba
de funcionalidad. La presencia histórica de un artefacto tampoco demuestra
explotación activa actual.

La categoría se elige en este orden:

1. Confirmación: `Earned the hype` si Hype >= 6; `Sleeper` en otro caso.
2. Sin confirmación ni EPSS válido/fresco: `Unknown`.
3. EPSS >= 0,70 o PoC público curado: `Watch`.
4. Hype >= 7 y Reality < 5: `Overhyped` (etiqueta visual: atención superior al
   índice de amenaza; no afirma que el CVE sea inocuo).
5. Resto: `Quiet`, que tampoco significa ausencia de explotación.

La regla 3 evita que una predicción alta o un PoC público aparezcan como una
conclusión tranquilizadora. Las alertas incluyen reglas explícitas de
confirmación y Watch. La cola operativa incluye explotaciones confirmadas aunque
el CVE se publicara hace años; las tablas cronológicas conservan sus fechas.

## Atención

```text
Media = min(número de historias de prensa recientes distintas / 2, 10)
Hype = 0.60*Media + 0.25*Tone + 0.15*Branding
```

Tone está en 0–10; Branding es 0 o 10. Solo cuentan historias de prensa con
fecha en los últimos 30 días y no futura. Advisories, catálogos y documentos de
tipo desconocido no aumentan Media. Se eliminan parámetros comunes de tracking;
un hash del titular normalizado agrupa republicaciones con el mismo titular.
Esto no resuelve toda la sindicación semántica ni toda la atribución editorial.

CVSS y popularidad de repositorios permanecen visibles como dimensiones
separadas; no aumentan atención ni duplican directamente el predictor EPSS.
Si no hay prensa reciente, el tono/branding histórico no sostiene Hype.
El tono usa una muestra de hasta cinco titulares por CVE, con método/modelo
registrado. El laboratorio usa la heurística determinista, sin llamadas LLM.

Los nombres sugeridos por el modelo deben aparecer en el texto. Los CVE deben
figurar en el título/resumen/URL recibidos. Las heurísticas no convierten CamelCase
de productos como OpenSSL/SharePoint en branding. Estas defensas reducen errores;
no sustituyen una evaluación humana de precisión y atribución.

## Fuentes y persistencia

- `evidence`: observación por CVE, fuente, tipo e identificador externo, con URL,
  fecha, contenido, confianza y estado. Exploit-DB mantiene IDs y metadatos.
- `github_poc_count` y `exploitdb_poc_count`: contadores independientes.
  `poc_count` es un máximo de compatibilidad, no una unión deduplicada de exploits.
  Un cero o fallo de GitHub no elimina la evidencia de Exploit-DB.
- `epss_date`/`epss_model`: procedencia del snapshot. Las fechas futuras o
  caducadas no habilitan clasificación predictiva. Un snapshot vacío falla.
- `source_runs`: SUCCESS/PARTIAL/ERROR por fuente. Una fuente fallida no cancela
  las demás. Intel guarda watermarks independientes; los fallos parciales no
  se anuncian como un ciclo plenamente satisfactorio.
- GHSA lee `cvss_severities`, conserva vector/proveedor y descarta retirados.
  El worker combina páginas recientes con un cursor de backfill para progresar
  por el histórico sin repetir solamente el mismo bloque. El lab toma una muestra
  acotada de 500 advisories y lo declara en el informe.
- CIRCL filtra sightings `exploited` y conserva autor/fuente/fecha. Solo un UUID
  presente en `CIRCL_TRUSTED_AUTHORS` puede activar confirmación. La lista vacía
  no declara confiables todos los reportes públicos. El lab limita la muestra
  de CIRCL y registra truncamiento/error; no afirma cobertura completa.
- RSS consume las dos listas configuradas (35 feeds), clasifica advisories y
  conserva varios CVE explícitos por entrada. Las búsquedas adicionales rotan
  mediante deadlines; un top fijo no monopoliza indefinidamente la cola.
- Un registro REJECTED no se importa como CVE normal; una actualización que
  rechaza un CVE elimina su score actual y conserva su historia.

## Reproducibilidad y volumen

El scoring compara fingerprints versionados en SQL, pagina por CVE y escribe
lotes de hasta 2.000. `score_evaluations` conserva el snapshot exacto de las
señales, metadatos de fuentes, versión y resultado por fingerprint, incluso
cuando cambia la entrada pero no el valor redondeado. `score_history` conserva
los cambios numéricos o de categoría para la visualización.

El detalle muestra componentes derivados del snapshot usado para calcular el
score, no una fórmula distinta basada en el estado actual de otras tablas.
Los números no finitos o fuera de rango se rechazan/normalizan; los constraints
de PostgreSQL impiden nuevos scores inválidos. Los constraints sobre tablas
anteriores se instalan NOT VALID: se debe auditar el legado antes de validarlos.

El laboratorio tiene PostgreSQL propio y casos públicos reales de todo el mirror.
Los bytes de fuentes se conservan por SHA-256, junto con URL, fechas y reportes.
Ver [el runbook y resultados](SCORING_LAB.md).

## Qué quedó validado y qué no

Quedaron automatizados los contraejemplos de seguridad de la auditoría, tests
unitarios/integración, carga con volumen real, consistencia de estados, límites
numéricos, replay de snapshots y pasada incremental sin cambios.

Los pisos 7/5,9, los pesos 60/25/15, las ventanas 30/7 días y el umbral 0,70 son
decisiones de producto documentadas; no parámetros ajustados estadísticamente.
El backtest de tres cohortes mide nuevas incorporaciones en KEV a 30 días y no
demuestra mejora predictiva respecto a EPSS. No evalúa todo ataque real, ni la
exactitud editorial del tono/branding, ni el riesgo de un inventario concreto.
No se presenta el índice como un predictor perfecto ni como una probabilidad.
