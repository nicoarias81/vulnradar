# Revisión del scoring y de las fuentes

Esta es la auditoría histórica anterior a las correcciones. La implementación
y los resultados actuales están en [SCORING_V4.md](SCORING_V4.md) y
[SCORING_LAB.md](SCORING_LAB.md). Los contraejemplos originales se conservan
con sus hashes para comparar versiones.

Fecha: 1 de noviembre de 2026. Estado inicial: **el modelo no está validado para
priorización operativa**. Esta revisión no modifica las fórmulas ni los datos
de producción. Separa errores reproducibles de decisiones metodológicas que
requieren definir objetivos y contrastarlos con datos independientes.

## Evidencia y alcance

- Auditoría offline: `python scripts/audit_scoring.py`. No usa red ni una base
  persistente. Comprueba 25.920 combinaciones normalizadas: ambas puntuaciones
  permanecen entre 0 y 10. También verifica monotonía numérica individual.
- El mismo programa documenta **11 contraejemplos seleccionados** de semántica,
  integridad o cobertura. No son una muestra aleatoria ni una tasa de error.
  Devuelve código 1 mientras esos requisitos propuestos no se cumplan.
- [Resultados reproducibles](scoring-audit/2026-11-01-counterexamples.json).
- [Sondeo de fuentes](scoring-audit/2026-11-01-sources.json): 35 feeds consultados
  desde esta estación; 34 respondieron con HTTP 200 y entradas parseables. El RSS
  de Exploit-DB agotó el timeout. Esto no demuestra una caída permanente ni
  disponibilidad desde producción. Se limita cada lectura a 2 MiB.
- [Inspección de PostgreSQL local](scoring-audit/2026-11-01-local-data.json) en
  modo de solo lectura: 26.730 CVEs, 25.256 enriquecimientos y solamente 8 scores.
  Se comprobó que los 8 identificadores coinciden con el seed demo; no
  constituyen un conjunto de validación de precisión. De los
  enriquecimientos, 25.248 no tienen EPSS. Esta instantánea local no representa
  la cobertura del despliegue público.
- La suite de regresión de la revisión de código anterior pasó 210 pruebas.
  En esta revisión se reejecutaron las 42 pruebas de scoring: todas pasan.
  Comprobar que una fórmula implementa los pesos elegidos no valida esos pesos
  ni la interpretación del resultado. No se ha hecho un backtest temporal.

## Hallazgos

### 1. Alta: explotación conocida puede etiquetarse como Overhyped

En `core/scoring.py`, un caso con KEV, EPSS 0,01, Ease 10, CVSS 9,8, Media 10,
Tone 9 y branding obtiene **Hype 8,26, Reality 4,53, Overhyped**. La etiqueta del
dashboard para esa categoría es `NO EVIDENCE OF USE`, incompatible con KEV.

Además, sin KEV y sin ransomware el máximo teórico es:

```text
2,5 EPSS + 1,5 PoC + 1,0 explotación observada + 0,5 Ease = 5,5
```

Por tanto, una explotación confirmada fuera de KEV no puede alcanzar Reality 6
ni las categorías Sleeper/Earned the hype. En el pipeline actual, ransomware
procede de KEV, de modo que el catálogo se convierte de hecho en una puerta de
entrada para la zona de Reality alto. La fórmula no expresa esa decisión.

Corrección propuesta: separar un estado de explotación observado y trazable
de la estimación predictiva. Una confirmación fiable debe bloquear etiquetas
que nieguen evidencia de uso, sin depender de EPSS ni de la cantidad de PoC.
No basta con subir arbitrariamente el peso de KEV o asignar a todo KEV un 10.

### 2. Alta: las fuentes de PoC se pisan y no miden la misma cosa

`agents/intel_agent.py:sync_exploitdb` escribe el máximo entre el contador actual
y los exploits de Exploit-DB. `agents/enrichment_agent.py:upsert_poc_count`
reemplaza ese mismo campo por resultados de GitHub. Reproducción con las
sentencias reales en SQLite en memoria:

```text
Exploit-DB: 2 → GitHub sin resultados: 0 → siguiente carga de Exploit-DB: 2
```

El score puede oscilar sin que cambie la evidencia real. Un cero exitoso de
GitHub solo significa que esa consulta no encontró repositorios, no que hayan
desaparecido los exploits de otras fuentes.

Además, GitHub `total_count` cuenta coincidencias de una búsqueda de
repositorios, no exploits verificados. No se inspecciona la evidencia, no se
comprueba `incomplete_results` y se mezclan unidades diferentes: repositorios
GitHub y entradas Exploit-DB. Cinco coincidencias saturan la contribución de
PoC tanto en Hype como en Reality. La cantidad no acredita cinco capacidades
independientes ni cinco implementaciones funcionales.

Corrección propuesta: observaciones por fuente y artefacto, con URL, identificador,
fecha, tipo, estado de validación y vínculos de duplicidad. Derivar por separado
`public_poc_present`, `validated_exploit_present` y atención a repositorios.
Un fallo o ausencia de resultados de una fuente no debe borrar otra fuente.
La [API de búsqueda de GitHub](https://docs.github.com/en/rest/search/search)
documenta respuestas incompletas y límites de resultados; no acredita calidad
ni funcionalidad del código encontrado.

### 3. Alta: diez feeds configurados no se descargan

`enrichment_agent.run()` pasa solo `sources.rss` al argumento `feeds` de
`load_rss()`. `rss_regex_only` únicamente se convierte en un conjunto para
decidir si saltar el LLM: sus URLs no se añaden al bucle de descarga.

La ejecución real del orquestador con HTTP simulado registra 25 peticiones y
**0 de los 10 feeds de advisories**: MSRC, Cisco, ZDI, Palo Alto, Ivanti,
Fortinet, CERT-FR, INCIBE, CERT-EU y Exploit-DB. No es una caída de esos servicios.

La solución requiere unir las listas y probar cada URL configurada. También
hay que introducir tipos de documento: un advisory de proveedor o una entrada
de catálogo no debería aumentar automáticamente la misma variable de atención
mediática que una noticia independiente. Activar los diez feeds sin distinguir
esos tipos cambiaría Hype por una razón administrativa.

### 4. Alta: datos desconocidos se convierten en ausencia de amenaza

`build_normalized_cve()` transforma EPSS ausente, tono desconocido y otros
campos no observados en cero/falso. El audit demuestra que datos completamente
ausentes y datos explícitamente iguales a cero producen las mismas señales.

Un CVE recién publicado, una fuente caída o una cola no procesada puede
presentarse como Quiet sin distinguir la falta de información. `updated_at`
es común al enriquecimiento: una actualización de tono puede ocultar que EPSS
es antiguo. KEV y wild son flags acumulativos sin fecha/evidencia por observación.

Corrección propuesta: estados `unknown`, `observed_absent`, `observed_present`
y `stale`, con timestamps por fuente. Mostrar completitud/confianza aparte.
No renormalizar automáticamente los pesos faltantes: podría producir valores
extremos a partir de una sola señal. Definir qué etiquetas quedan bloqueadas
cuando la información necesaria es desconocida o está caducada.

### 5. Alta: atribución y branding del LLM no están anclados a evidencia

`rerank_entries()` solo comprueba el formato del CVE devuelto, no que figure en
el texto enviado al modelo. El audit entrega un titular con CVE-2026-1234 y una
respuesta inventada con CVE-2026-99999: el código la acepta. Lo mismo ocurre con
el nickname. Una instrucción en el prompt no sustituye esa validación.

La heurística identifica **OpenSSL** y **SharePoint** como nombres comerciales
de vulnerabilidades, aportando hasta 1,5 puntos de Hype sin un branding real.
Pwn2Own aparece también como nombre conocido aunque es un evento. El tono se
calcula sobre un único titular por CVE, no una muestra representativa; la última
inserción puede sobrescribir un nickname previamente confirmado mediante
`upsert_tone()`. El origen `llm`/`heuristic` generado no queda persistido.

Corrección propuesta: aceptar IDs y nombres presentes en evidencia citada;
extraer primero todos los CVE explícitos y usar el LLM como ayuda de atribución.
Conservar fragmentos, versión de prompt/modelo, salida y método. Agregar el tono
de varias publicaciones independientes, con tratamiento explícito del fallback.
No enviar contenido no confiable al modelo como si fuera una instrucción.

### 6. Media: Ease interpreta incorrectamente CVSS 4 y acepta vectores inválidos

`exploit_ease('garbage')` devuelve **10**, el máximo. Un vector CVSS 4 con
`AT:P` y `UI:A` obtiene el mismo 10 que uno sin esas restricciones, porque el
parser solo busca substrings de CVSS 3 y `UI:R`. Incluso métricas modificadas
como `MAV:L` pueden coincidir por substring con `AV:L`.

La [especificación de FIRST](https://www.first.org/cvss/v4.0/specification-document)
define AT y los valores UI N/P/A. El problema es el parser y la heurística;
el número Ease no es una métrica oficial de CVSS.

Corrección propuesta: parser por versión y por claves completas, validación de
métricas obligatorias y vectores inválidos como desconocidos. Conservar vector,
versión y proveedor. Revisar si Ease aporta señal adicional a EPSS antes de
mantener el peso del 5 %. El orden actual de preferencia 3.1 → 3.0 → 4.0 debe
ser una política explícita, no confundirse con equivalencia entre versiones.

### 7. Media: no hay garantías numéricas ante entradas anómalas

Los 25.920 casos normalizados respetan los límites y cada señal aislada es
monótona. Sin embargo, entradas negativas producen Hype -5,25 y Reality -3,75;
`exploit_ease=Infinity` produce Reality infinito. La normalización acepta
NaN/infinito como floats y el esquema no tiene CHECK de rangos.

No se han observado esos valores en producción; es un fallo de validación
reproducible. Validar tipos, finitud y dominios al ingerir, al puntuar y mediante
constraints. Los valores inválidos deben generar una incidencia de calidad,
no convertirse silenciosamente en evidencia positiva o en ausencia de riesgo.

### 8. Alta: la noción temporal de Hype no está definida ni validada

`media_count` acumula URLs durante toda la vida del CVE. No hay ventana temporal,
decaimiento, normalización por exposición ni deduplicación de sindicación o de
URLs con parámetros. Veinte URLs saturan Media: una campaña antigua puede
mantener permanentemente la misma contribución que una noticia de hoy.

Además, CVSS y PoC aportan hasta 3,5 puntos de Hype sin cobertura mediática.
Esto puede ser defendible si Hype significa una mezcla de severidad publicada
y atención, pero no si se presenta como una medición de exageración o ruido.

Corrección propuesta: decidir si Hype representa atención actual o notoriedad
histórica, y mostrar ambas si son útiles. Para atención actual, contrastar
ventanas 7/30 días y agregación por dominio/cluster de historia; validar la
escala con anotaciones humanas. Separar severidad técnica de ruido. No elegir
un logaritmo, pesos o ventanas como si ya estuvieran empíricamente calibrados.

### 9. Alta: una explotación observada puede quedar fuera de Pay attention to

`dashboard/data.py:ACTIONABLE_WHERE` incluye KEV, EPSS ≥ 0,70 y PoC, pero no
`wild_confirmation`. Un caso confirmado en CIRCL sin esas otras señales queda
fuera. El rango por defecto del dashboard filtra por la fecha de publicación
del CVE en los últimos 30 días: una vulnerabilidad antigua explotada hoy puede
no aparecer en la vista inicial.

Además, el comentario del código describe EPSS 0,70 como el percentil superior
30 %, pero compara probabilidad, no `epss_percentile`. El umbral puede elegirse
como probabilidad; su explicación y justificación deben coincidir.

Corrección propuesta: alertas y cola operativa compartiendo el mismo estado de
explotación fiable. Separar fecha de publicación de fecha de nueva evidencia.
Las alertas por categoría tampoco sustituyen una regla explícita de explotación
confirmada cuando la categoría puede quedarse en Quiet/Overhyped.

### 10. Media: contratos, cobertura y aislamiento de fuentes incompletos

| Fuente | Uso razonable | Problema actual |
|---|---|---|
| CVE List V5 | Identidad y datos publicados por CNA/ADP | No conserva estado operativo; acepta REJECTED como registro normal y puede seguir puntuándolo por `raw_json`. Guarda solo un producto y una métrica CVSS. |
| CISA KEV | Evidencia fuerte de explotación conocida | Buena fuente y mirror oficial; falta reconciliar retractaciones/cambios y guardar versión de catálogo por observación. |
| FIRST EPSS | Predicción global a 30 días | Se descartan `model_version` y `score_date`; falta distinguir no cubierto de cero y detectar datos obsoletos/incompletos. |
| Exploit-DB | Artefactos públicos para revisión | Se pierden IDs, URLs, fechas y verificación al reducir todo a un contador compartido. |
| GitHub Search | Descubrimiento de candidatos a PoC | Consulta con `poc` puede perder exploits sin esa palabra; coincidencias y popularidad no prueban funcionalidad. |
| CIRCL sightings | Observaciones con tipo, autor y fuente | Usar solo `exploited` es mejor que usar `seen`, pero hoy se pierde fuente, autor, fecha y nivel de confianza. La carga inicial mira solo una ventana reciente. |
| GHSA | Métricas complementarias y avisos de paquetes | Repite las primeras 500 entradas, no un histórico completo; no conserva vector ni proveedor y no trata `withdrawn_at`. |
| RSS/CERT/vendor | Documentación y atención, según tipo | Diez feeds no consumidos; el rerank conserva un solo CVE por noticia y puede omitir otros explícitos. |
| Google News / HN | Cobertura adicional | Google agrega URLs distintas de las originales; el fallback HN cambia el universo observado. La cola de 15 CVEs repite un top fijo sin watermark de búsqueda. |

GitHub [anunció deprecación de `cvss`](https://github.blog/changelog/2025-03-27-deprecation-of-cvss-field-in-security-advisories-api/)
en favor de `cvss_severities`. El código sigue usando `cvss`. **El sondeo actual
devuelve ambos campos**, por lo que no se afirma que el endpoint esté roto hoy;
sí existe una dependencia de un contrato anunciado como deprecado.

En enriquecimiento, un fallo de KEV/EPSS puede impedir RSS, GitHub y tono. En
Intel, un fallo de Exploit-DB impide CIRCL/GHSA; un fallo final de GHSA puede
revertir los cambios anteriores al compartir transacción. Páginas fallidas o
truncadas de sightings pueden acabar con un watermark diario de éxito parcial.
Se necesitan resultados y watermarks por fuente, reintentos acotados y estado
explícito de cobertura parcial.

### 11. Metodológico: se mezclan observación, predicción y proxies correlacionados

EPSS estima explotación en los próximos 30 días y no riesgo organizacional,
según [FIRST](https://www.first.org/epss/faq). Su modelo utiliza características
CVSS, código de explotación y atención como entradas, según su
[metodología](https://www.first.org/epss/how-it-works). Por ello, sumarle otra vez
Ease/PoC no constituye evidencia independiente ni garantiza mejorar la predicción.
Combinar señales correlacionadas no es por sí mismo un error matemático; requiere
calibración y estudios de ablación para justificar pesos y evitar sobrecontar.

El estado observado podría seguir la distinción de
[CERT/CC SSVC](https://certcc.github.io/SSVC/reference/decision_points/exploitation/)
entre ausencia de evidencia, PoC público y explotación activa, añadiendo
`unknown` y confianza como decisiones del producto. La documentación de
[CIRCL](https://www.vulnerability-lookup.org/user-manual/sightings/) distingue
explícitamente PoC publicado de explotación observada: no deben intercambiarse.

### 12. Metodológico: la historia no permite reproducir y calibrar el modelo

`score_history` guarda valores/categoría/fecha, pero no snapshot de entradas,
versión de fórmula, versiones de fuentes, método de tono ni evidencias. El hash
actual permite detectar cambios, pero no reconstruir las entradas históricas.
Un cambio de modelo EPSS, de prompt o de cobertura puede parecer evolución de
amenaza sin poder distinguirlo. No se encontró un benchmark independiente ni
validación temporal de los umbrales.

## Diseño recomendado antes de cambiar pesos

Mantener los dos ejes como presentación, pero separar estos conceptos en datos:

1. **Estado de explotación**: unknown / no-evidence / public-poc /
   confirmed-exploitation, con fuentes, confianza y fechas. La ausencia de
   evidencia no implica que no exista explotación.
2. **Predicción**: EPSS original, fecha y versión. No convertir Reality/10 en
   probabilidad ni presentar el índice como riesgo del entorno.
3. **Atención**: cobertura deduplicada, tipo de fuente, ventana temporal,
   diversidad y tono agregado auditable. Severidad y branding son dimensiones
   explicativas separadas hasta demostrar que conviene incluirlas.
4. **Severidad y aplicabilidad**: CVSS con procedencia y contexto de activos
   cuando exista inventario. Una amenaza global no determina por sí sola el
   riesgo de una organización.
5. **Índice Reality**: si se conserva, especificarlo como índice de priorización,
   con reglas de coherencia respecto a los estados anteriores y validación de
   la escala. Los umbrales de categoría deben derivarse del objetivo del producto.

## Plan de validación y criterios de salida

### Antes de recalibrar

- Corregir cobertura de feeds, contadores por fuente, CVE rechazados, contratos
  API, validación numérica y atribución del LLM. Cubrirlos con tests de contrato
  y pruebas de integración que recorran el orquestador real.
- Guardar snapshots fechados de entradas y evidencia, versiones de algoritmo,
  EPSS, prompt/modelo y clasificación de documentos. Establecer ventanas de
  frescura por fuente y alarmas por caída brusca de cobertura.
- Llevar los contraejemplos de esta auditoría a requisitos explícitos y lograr
  cero violaciones de los requisitos de seguridad acordados. No ocultarlos
  cambiando solo los valores esperados en los tests.

### Evaluación independiente

- Construir cohortes por fecha con casos conocidos, CVEs nuevos, antiguos
  recientemente explotados, sin CVSS, sin EPSS, con PoC falso/duplicado y con
  fuentes contradictorias. Etiquetar calidad de PoC, explotación y exageración
  por separado; revisar desacuerdos entre analistas.
- Congelar las entradas disponibles en el momento t. Evaluar explotación futura
  en t+30 con evidencia posterior que no se utilice como entrada en t. No usar
  KEV contemporáneo simultáneamente como feature y como etiqueta para demostrar
  supuesta capacidad predictiva. Un CVE que no aparece en KEV no es por ello un
  negativo confirmado.
- Comparar el modelo con baselines: explotación confirmada primero; después
  EPSS; y la fórmula actual. Medir precision/recall a un presupuesto top-K,
  curva precision-recall, tiempo hasta detección y resultados por cohorte.
  Estimar incertidumbre y reportar lagunas de cobertura.
- Para Hype, usar anotación humana independiente de atención y exageración;
  medir acuerdo y estabilidad por fuente/idioma. No usar el mismo LLM como
  productor y juez de sus propias etiquetas.
- Si se decide publicar una probabilidad nueva, entrenarla/calibrarla y evaluar
  calibración y Brier score en holdout temporal. No aplicar esa interpretación
  a un índice heurístico 0–10 sin modelo probabilístico.
- Probar ablaciones retirando PoC, Ease, branding y tono. Mantenerlos solo si
  aportan utilidad frente a EPSS y las reglas de evidencia, con un criterio de
  mejora acordado antes de ver el conjunto de prueba.
- Comparar una versión candidata en modo sombra, con snapshots compartidos,
  antes de cambiar alertas o categorías públicas. No se ha hecho ese despliegue
  ni esa calibración como parte de esta revisión.

## Orden de trabajo

1. Integridad de fuentes y separación de observaciones: hallazgos 2, 3, 5, 6,
   7 y 10.
2. Semántica de explotación, desconocidos y cola operativa: 1, 4 y 9.
3. Temporalidad de atención y trazabilidad: 8 y 12.
4. Backtest, evaluación de Hype y calibración de pesos: 11 y plan anterior.

El resultado defendible es un sistema con límites conocidos y calidad medida.
La aritmética actual es consistente en su dominio normalizado; la semántica,
la cobertura y la precisión operativa todavía no justifican afirmar que el
scoring funciona perfectamente.
