"""
Intel Agent — explotación observada y PoC públicos, sin LLM.

Tres fuentes estructuradas, cada una escribe sólo sus columnas y es idempotente:

- Exploit-DB (CSV público, ~10 MB): CVE -> exploits. Alimenta ``poc_count``.
  Reemplaza de hecho al search de GitHub, que sin token devuelve 403 y dejó
  la señal en 20 CVEs sobre 398 mil.
- CIRCL Vulnerability-Lookup: sightings de honeypots (Shadowserver), MISP y
  KEV agregado. Alimenta ``wild_confirmation``, que sin esta fuente queda en 0
  en toda la base por más que el score lo premie.
- GitHub Security Advisories (API pública, 60 req/h): CVSS del advisory
  cuando el CNA no lo declaró. Hoy falta en el 46% de los CVEs.

Uso:
    python -m agents.intel_agent --all
    python -m agents.intel_agent --sightings --days 7
    python -m agents.intel_agent --exploitdb --csv /ruta/files_exploits.csv
"""
import argparse
import csv
import io
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.db import get_db, init_db  # noqa: E402

EXPLOITDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
CIRCL_SIGHTINGS_URL = "https://vulnerability.circl.lu/api/sighting/"
GHSA_URL = "https://api.github.com/advisories"
USER_AGENT = "vulnradar/0.3 (+https://github.com/nicoarias81/vulnradar)"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
INTEL_STATE_KEY = "intel_last_run"
# Un sighting sólo prueba explotación si dice explícitamente que se explotó.
EXPLOITED_TYPES = {"exploited"}

POC_COUNT_SQL = """
    INSERT INTO enrichments (cve_id, poc_count) VALUES (?, ?)
    ON CONFLICT(cve_id) DO UPDATE SET
        poc_count = CASE
            WHEN excluded.poc_count > COALESCE(enrichments.poc_count, 0)
            THEN excluded.poc_count
            ELSE COALESCE(enrichments.poc_count, 0)
        END,
        updated_at = CURRENT_TIMESTAMP
"""

WILD_SQL = """
    INSERT INTO enrichments (cve_id, wild_confirmation) VALUES (?, 1)
    ON CONFLICT(cve_id) DO UPDATE SET
        wild_confirmation = 1,
        updated_at = CURRENT_TIMESTAMP
"""


def parse_exploitdb(csv_text: str) -> dict:
    """``{cve: [edb_id, ...]}`` desde el CSV oficial de Exploit-DB.

    La columna ``codes`` trae ``CVE-2021-44228;CVE-2021-45046`` además de IDs
    OSVDB; se descarta todo lo que no sea un CVE bien formado.
    """
    por_cve: dict[str, list[int]] = {}
    for fila in csv.DictReader(io.StringIO(csv_text)):
        edb_id = (fila.get("id") or "").strip()
        if not edb_id.isdigit():
            continue
        for codigo in (fila.get("codes") or "").split(";"):
            codigo = codigo.strip().upper()
            if CVE_RE.match(codigo):
                por_cve.setdefault(codigo, []).append(int(edb_id))
    return por_cve


def sync_exploitdb(conn, *, csv_text=None, session=None, url=EXPLOITDB_URL,
                   timeout=240) -> dict:
    """Carga el catálogo de Exploit-DB y lo vuelca en ``poc_count``.

    Nunca reduce el contador: el search de GitHub puede haber visto más PoCs.
    """
    if csv_text is None:
        http = session or requests
        respuesta = http.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
        respuesta.raise_for_status()
        csv_text = respuesta.text

    por_cve = parse_exploitdb(csv_text)
    with_ids = {cve: len(ids) for cve, ids in por_cve.items() if ids}
    if not with_ids:
        return {"cves": 0, "con_exploit": 0}

    # Orden determinista: dos procesos que insertan el mismo conjunto en
    # distinto orden se bloquean mutuamente y Postgres corta con deadlock.
    pares = sorted(with_ids.items())
    conn.executemany(
        "INSERT INTO cves (cve_id) VALUES (?) ON CONFLICT (cve_id) DO NOTHING",
        [(cve,) for cve, _ in pares],
    )
    conn.executemany(POC_COUNT_SQL, pares)
    return {"cves": len(por_cve), "con_exploit": len(with_ids)}


def fetch_sightings_page(date_from, *, page=1, per_page=1000, session=None,
                         timeout=60) -> dict:
    http = session or requests
    params = {"date_from": date_from, "page": page, "per_page": per_page}
    respuesta = http.get(CIRCL_SIGHTINGS_URL, params=params, timeout=timeout,
                         headers={"User-Agent": USER_AGENT})
    respuesta.raise_for_status()
    return respuesta.json()


def sync_sightings(conn, *, days=7, date_from=None, max_pages=400, session=None,
                   timeout=60, per_page=100) -> dict:
    """Marca ``wild_confirmation`` para CVEs con sintoma de explotación real.

    Pagina la API pública de CIRCL desde ``date_from`` (o hoy - ``days``) y se
    queda sólo con los sightings de tipo ``exploited``: un ``seen`` es una
    mención, no una prueba de que alguien lo haya explotado.

    ``per_page`` va bajo a propósito: con 1000 la API devuelve ~23 MB por
    página y la respuesta se corta (JSONDecodeError) en el server de prod.
    Una página que falla se saltea en vez de tumbar la corrida entera.
    """
    if date_from is None:
        date_from = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")

    vistos = 0
    explotados = set()
    paginas = 0
    fallidas = 0
    for page in range(1, max_pages + 1):
        payload = None
        for intento in (1, 2):
            try:
                payload = fetch_sightings_page(date_from, page=page, per_page=per_page,
                                               session=session, timeout=timeout)
                break
            except (ValueError, requests.RequestException):
                payload = None
        if payload is None:
            fallidas += 1
            # Un corte de red no debe costar la señal de todo el día.
            if fallidas >= 3:
                break
            continue
        datos = payload.get("data") or []
        if not datos:
            break
        paginas += 1
        vistos += len(datos)
        for sighting in datos:
            if (sighting.get("type") or "").lower() in EXPLOITED_TYPES:
                cve = (sighting.get("vulnerability") or "").strip().upper()
                if CVE_RE.match(cve):
                    explotados.add(cve)
        total = (payload.get("metadata") or {}).get("count") or 0
        if vistos >= total:
            break

    if explotados:
        ordenados = sorted(explotados)
        conn.executemany(
            "INSERT INTO cves (cve_id) VALUES (?) ON CONFLICT (cve_id) DO NOTHING",
            [(cve,) for cve in ordenados],
        )
        conn.executemany(WILD_SQL, [(cve,) for cve in ordenados])

    return {"date_from": date_from, "sightings": vistos, "paginas": paginas,
            "paginas_fallidas": fallidas, "cves_explotados": len(explotados)}


def fetch_ghsa_page(*, page=1, per_page=100, session=None, timeout=60) -> list:
    http = session or requests
    cabeceras = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    respuesta = http.get(GHSA_URL, params={"type": "reviewed", "page": page,
                                           "per_page": per_page},
                         headers=cabeceras, timeout=timeout)
    respuesta.raise_for_status()
    return respuesta.json()


def sync_ghsa(conn, *, pages=5, session=None, timeout=60) -> dict:
    """Rellena ``cvss_score`` sólo donde el CNA no lo declaró."""
    revisados = 0
    rellenados = 0
    for page in range(1, pages + 1):
        for advisory in fetch_ghsa_page(page=page, session=session, timeout=timeout):
            revisados += 1
            cve = (advisory.get("cve_id") or "").strip().upper()
            cvss = (advisory.get("cvss") or {}).get("score")
            severidad = advisory.get("severity") or ""
            if not CVE_RE.match(cve) or cvss is None:
                continue
            # RETURNING en vez de rowcount: psycopg no siempre lo reporta y el
            # conteo terminaba en 0 con las filas igual actualizadas.
            cur = conn.execute(
                """UPDATE cves SET cvss_score = ?, cvss_severity = ?
                   WHERE cve_id = ? AND cvss_score IS NULL
                   RETURNING cve_id""",
                (float(cvss), severidad.lower() or None, cve),
            )
            rellenados += len(cur.fetchall() or [])
    return {"advisories": revisados, "cvss_rellenados": rellenados}


def run_daily(conn, *, hours=24, force=False, days=None, ghsa_pages=5) -> dict:
    """Corre las tres fuentes si pasó la ventana; si no, no hace nada.

    El worker cicla cada 15 minutos y el catálogo de Exploit-DB son 10 MB: bajar
    y repaginar CIRCL en cada vuelta sería tirar red y cuota al piso.
    """
    from agents.sync_agent import get_state, set_state

    ahora = datetime.now(timezone.utc)
    ultimo = get_state(conn, INTEL_STATE_KEY)
    if ultimo and not force:
        try:
            previo = datetime.fromisoformat(ultimo.replace("Z", "+00:00"))
            if (ahora - previo) < timedelta(hours=hours):
                return {"skipped": True, "last_run": ultimo}
        except ValueError:
            pass  # un valor corrupto no debe bloquear la corrida

    resumen = {
        "exploitdb": sync_exploitdb(conn),
        "sightings": sync_sightings(conn, days=days or max(1, int(hours) // 24 + 1)),
        "ghsa": sync_ghsa(conn, pages=ghsa_pages),
    }
    set_state(conn, INTEL_STATE_KEY, ahora.isoformat(timespec="seconds"))
    return resumen


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Fuentes de intel estructuradas")
    parser.add_argument("--exploitdb", action="store_true", help="cargar Exploit-DB")
    parser.add_argument("--sightings", action="store_true", help="sightings de CIRCL")
    parser.add_argument("--ghsa", action="store_true", help="GitHub Advisories (CVSS)")
    parser.add_argument("--all", action="store_true", help="las tres")
    parser.add_argument("--days", type=int, default=7, help="ventana de sightings")
    parser.add_argument("--csv", help="CSV local de Exploit-DB (evita la descarga)")
    parser.add_argument("--pages", type=int, default=5, help="páginas de GHSA")
    args = parser.parse_args(argv)

    if not (args.all or args.exploitdb or args.sightings or args.ghsa):
        parser.error("elegí al menos una fuente (--all, --exploitdb, --sightings, --ghsa)")

    init_db()
    conn = get_db()
    try:
        if args.all or args.exploitdb:
            csv_text = Path(args.csv).read_text(encoding="utf-8") if args.csv else None
            print("exploitdb:", sync_exploitdb(conn, csv_text=csv_text))
        if args.all or args.sightings:
            print("sightings:", sync_sightings(conn, days=args.days))
        if args.all or args.ghsa:
            print("ghsa:", sync_ghsa(conn, pages=args.pages))
        conn.commit()
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
