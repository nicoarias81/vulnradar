"""
Intel Agent — observed exploitation and public PoCs, no LLM.

Three structured sources, each one writes only its own columns and is idempotent:

- Exploit-DB (public CSV, ~10 MB): CVE -> exploits. Feeds ``poc_count``.
  It effectively replaces the GitHub search, which without a token returns 403
  and left the signal on 20 CVEs out of 398 thousand.
- CIRCL Vulnerability-Lookup: honeypot sightings (Shadowserver), MISP and
  aggregated KEV. Feeds ``wild_confirmation``, which without this source stays
  at 0 across the whole database no matter how much the score rewards it.
- GitHub Security Advisories (public API, 60 req/h): the advisory CVSS
  when the CNA did not declare one. It is missing on 46% of the CVEs today.

Usage:
    python -m agents.intel_agent --all
    python -m agents.intel_agent --sightings --days 7
    python -m agents.intel_agent --exploitdb --csv /path/files_exploits.csv
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
# A sighting only proves exploitation when it says so explicitly.
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
    """``{cve: [edb_id, ...]}`` built from the official Exploit-DB CSV.

    The ``codes`` column carries ``CVE-2021-44228;CVE-2021-45046`` alongside
    OSVDB ids; anything that is not a well-formed CVE is discarded.
    """
    por_cve: dict[str, list[int]] = {}
    for row in csv.DictReader(io.StringIO(csv_text)):
        edb_id = (row.get("id") or "").strip()
        if not edb_id.isdigit():
            continue
        for codigo in (row.get("codes") or "").split(";"):
            codigo = codigo.strip().upper()
            if CVE_RE.match(codigo):
                por_cve.setdefault(codigo, []).append(int(edb_id))
    return por_cve


def sync_exploitdb(conn, *, csv_text=None, session=None, url=EXPLOITDB_URL,
                   timeout=240) -> dict:
    """Loads the Exploit-DB catalog and writes it into ``poc_count``.

    It never lowers the counter: the GitHub search may have seen more PoCs.
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

    # Deterministic order: two processes inserting the same set in a different
    # order block each other and Postgres aborts with a deadlock.
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
    """Sets ``wild_confirmation`` for CVEs showing symptoms of real exploitation.

    Pages the public CIRCL API from ``date_from`` (or today - ``days``) and
    keeps only ``exploited`` sightings: a ``seen`` is a mention, not proof that
    someone exploited it.

    ``per_page`` is low on purpose: at 1000 the API returns ~23 MB per page and
    the response gets cut off (JSONDecodeError) on the prod server. A page that
    fails is skipped instead of taking the whole run down.
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
            # A network blip must not cost the whole day's signal.
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
    """Fills ``cvss_score`` only where the CNA did not declare one."""
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
            # RETURNING instead of rowcount: psycopg does not always report it
            # and the count ended at 0 with the rows updated anyway.
            cur = conn.execute(
                """UPDATE cves SET cvss_score = ?, cvss_severity = ?
                   WHERE cve_id = ? AND cvss_score IS NULL
                   RETURNING cve_id""",
                (float(cvss), severidad.lower() or None, cve),
            )
            rellenados += len(cur.fetchall() or [])
    return {"advisories": revisados, "cvss_rellenados": rellenados}


def run_daily(conn, *, hours=24, force=False, days=None, ghsa_pages=5) -> dict:
    """Runs the three sources when the window has elapsed; otherwise does nothing.

    The worker cycles every 15 minutes and the Exploit-DB catalog is 10 MB:
    downloading it and re-paging CIRCL every turn would throw network away.
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
            pass  # a corrupt value must not block the run

    summary = {
        "exploitdb": sync_exploitdb(conn),
        "sightings": sync_sightings(conn, days=days or max(1, int(hours) // 24 + 1)),
        "ghsa": sync_ghsa(conn, pages=ghsa_pages),
    }
    set_state(conn, INTEL_STATE_KEY, ahora.isoformat(timespec="seconds"))
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Structured intel sources")
    parser.add_argument("--exploitdb", action="store_true", help="cargar Exploit-DB")
    parser.add_argument("--sightings", action="store_true", help="sightings de CIRCL")
    parser.add_argument("--ghsa", action="store_true", help="GitHub Advisories (CVSS)")
    parser.add_argument("--all", action="store_true", help="all three")
    parser.add_argument("--days", type=int, default=7, help="ventana de sightings")
    parser.add_argument("--csv", help="CSV local de Exploit-DB (evita la descarga)")
    parser.add_argument("--pages", type=int, default=5, help="GHSA pages")
    args = parser.parse_args(argv)

    if not (args.all or args.exploitdb or args.sightings or args.ghsa):
        parser.error("choose at least one source (--all, --exploitdb, --sightings, --ghsa)")

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
