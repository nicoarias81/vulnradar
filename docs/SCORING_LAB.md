# Laboratorio local de scoring con volumen real

El proyecto Compose `vulnradar-lab` usa su propia base `radar_lab`, usuario
`radar_lab`, contraseña local `radar_lab_local` y volumen `vulnradar-lab_lab-db`.
No usa las bases existentes ni la de producción. El cargador exige explícitamente
`VULNRADAR_LAB=1` y verifica el nombre real de la base antes de importar.

## Ejecución automática

Desde la raíz del proyecto en PowerShell:

```powershell
.\scripts\lab.ps1
.\scripts\lab.ps1 -ValidateOnly
```

El primer comando construye la imagen, inicia PostgreSQL, ejecuta la suite,
importa el mirror, carga fuentes, puntúa, valida, ejecuta los backtests y arranca
el dashboard. El segundo reutiliza los snapshots y datos persistidos: no vuelve
a descargar/importar todo el catálogo. Ambos conservan la base al terminar.

- Dashboard: [localhost:18501](http://localhost:18501).
- SOC local: [localhost:18501/soc](http://localhost:18501/soc), usuario `lab`,
  contraseña `radar-lab-local`.
- PostgreSQL: `localhost:55440`, base/usuario/clave indicados arriba.
  Se publica en loopback IPv4 e IPv6. También puede accederse sin depender del
  forwarding del host: `docker compose -f docker-compose.lab.yml exec postgres psql -U radar_lab -d radar_lab`.
  En esta máquina, psycopg y el sondeo TCP nativo del host agotaron el timeout
  hacia el puerto publicado. El acceso desde los contenedores y mediante ese
  comando psql está comprobado. No se ha cambiado la configuración global de
  red de Windows/Docker para forzar el forwarding.
- Caché e informes: `data/scoring-lab/` (no versionados).
- El mirror del proyecto se monta de solo lectura. Si falta un mirror git,
  el cargador clona uno independiente bajo el directorio persistente del lab.
- No se ejecutan exploits, no se envían alertas y no se realizan llamadas LLM.

Equivalentes multiplataforma:

```bash
docker compose -f docker-compose.lab.yml up -d postgres
docker compose -f docker-compose.lab.yml build runner
docker compose -f docker-compose.lab.yml run --rm runner
docker compose -f docker-compose.lab.yml run --rm runner python -m pytest -q -o addopts=--basetemp=/tmp/radar-tests -p no:cacheprovider
docker compose -f docker-compose.lab.yml run --rm runner python scripts/backtest_scoring.py --cohorts 2026-07-01,2026-08-01,2026-09-01 --cache /lab/cache --report /lab/backtest-cohorts.json
docker compose -f docker-compose.lab.yml up -d dashboard
```

Para refrescar los alias de fuentes actuales conservando versiones por hash:

```bash
docker compose -f docker-compose.lab.yml run --rm runner python scripts/build_scoring_lab.py --mirror /mirror --cache /lab/cache --report /lab/validation.json --refresh
```

Para apagar los servicios conservando la base:

```bash
docker compose -f docker-compose.lab.yml down
```

## Datos reales y aceptación

La carga del 1 de noviembre de 2026 importó **398.734 registros publicados** del
mirror y excluyó **18.859 rechazados**. El resto de filas de `cves` son stubs de
fuentes que se distinguen de los registros completos y no se puntúan como si
estuvieran normalizados. No se carga el seed demo.

Se almacenaron snapshots oficiales de EPSS, KEV y Exploit-DB, las URLs RSS
configuradas, una muestra GHSA y una muestra CIRCL acotada. Los fallos y límites
de las fuentes opcionales se conservan en `source_runs`; una muestra parcial
no equivale a falta de explotación.

La validación exige:

- Al menos 100.000 registros reales y cobertura EPSS de al menos el 90 % del
  volumen de registros reales; presencia de KEV y de PoC curados.
- Cero scores fuera de 0–10 y cero CVE rechazados con score actual.
- Cero explotaciones confirmadas con Reality < 7 o categorías tranquilizadoras.
- Cero violaciones en la auditoría offline independiente.
- Replay exacto de snapshots de evaluación, muestreado por categoría.
- Una segunda pasada con exactamente cero CVE recalculados.

`validation.json` registra los conteos, versiones, hashes, ejemplos públicos
(Heartbleed, EternalBlue, Log4Shell, MOVEit, XZ, PAN-OS y Tomcat), tiempos,
memoria del proceso y tamaño de la base. El JSON de evidencia versionado bajo
`docs/scoring-audit/` corresponde a esta ejecución; las ejecuciones siguientes
pueden tener distinta cobertura o distribución.

## Backtest temporal

La evidencia de esta ejecución está en
[validación](scoring-audit/2026-11-01-lab-v4.json),
[benchmark](scoring-audit/2026-11-01-benchmark-v4.json) y
[backtests](scoring-audit/2026-11-01-backtest-cohorts.json).

El benchmark completo de v4.1 procesó 398.734 registros en **82,024 s**
(aproximadamente 4.861 CVE/s), con **48,9 MiB** de memoria máxima del proceso.
La segunda pasada tardó **5,942 s** y no recalculó registros. Se ejecutó sobre
tablas temporales de salida para no cambiar los scores persistidos. El dashboard
respondió HTTP 200; la comprobación local midió aproximadamente 1,27 s para la
portada y 0,037 s para Log4Shell. Son mediciones de esta máquina y estas
instantáneas, no compromisos de latencia para otros despliegues.

La ejecución automática completa pasó **222 tests**, 13 checks de auditoría
offline y el replay de 96 evaluaciones reales, sin discrepancias. La base
persistente ocupa aproximadamente 2,1 GB en esta ejecución, incluidos índices
y snapshots de evaluación.

Para repetir el benchmark completo con salidas temporales:

```bash
docker compose -f docker-compose.lab.yml run --rm runner python scripts/benchmark_scoring.py
```

Las cohortes son 2026-07-01, 2026-08-01 y 2026-09-01, cada una con horizonte de
30 días. Para cada cohorte:

1. Recuperar el commit oficial de KEV disponible al cierre del día t y del día
   t+30, y el CSV histórico EPSS del día t.
2. Excluir los CVE ya conocidos en KEV en t.
3. Etiquetar como objetivo únicamente los nuevos KEV que ya tenían EPSS en t.
   Los CVE publicados después de t no estaban disponibles para puntuar.
4. Comparar ranking EPSS con el índice predictivo v4.1 sin inyectar PoC,
   publicaciones o información posterior al corte.

Los tamaños fueron **343.221**, **352.936** y **365.161** CVE elegibles. Los
objetivos observables dentro de esas cohortes fueron 12, 17 y 17. En top-1000,
EPSS y v4.1 capturaron respectivamente 0, 2 y 0 objetivos. El informe conserva
también top-100, top-500 y top-5000.

El resultado **no demuestra mejora predictiva frente a EPSS**. Sin históricos
de PoC, el componente predictivo de v4.1 es esencialmente una transformación
monótona y redondeada de EPSS. Las incorporaciones futuras a KEV no equivalen a
toda explotación ni a su fecha de comienzo; el resto de CVE no son negativos
confirmados. Tampoco se mide la exactitud de Hype con esas etiquetas.

Los cambios de v4.1 acreditados aquí son coherencia de estados, integridad,
trazabilidad y operación con volumen. Para ajustar pesos/predicción o medir
exageración editorial se necesitan etiquetas independientes y más cohortes.
