"""
Enrichment Agent — señales por CVE: KEV, EPSS, media (RSS), PoCs (GitHub)
y branding/tone_score (LLM).

Uso:
    python agents/enrichment_agent.py                 # corre todo
    python agents/enrichment_agent.py --rss-only      # sólo RSS (local)
    python agents/enrichment_agent.py --skip-llm      # sin llamadas al LLM
    python agents/enrichment_agent.py --llm-smoke     # 1 llamada real y sale

Cada fuente escribe SÓLO sus columnas: un INSERT OR REPLACE borraría el resto
de la fila de enrichments. En tests no hay red: las funciones de red aceptan
`session` y el paso LLM acepta un `completer` inyectable.
"""
import argparse
import csv
import gzip
import io
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_plus

import feedparser
import requests
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import llm as llm_client
from core.db import REPO_ROOT, ensure_cve_stub, get_db, init_db

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# cisa.gov responde 403 "Access Denied" (Akamai) a IPs de datacenter: el repo oficial kev-data
# publica el mismo catálogo en JSON, con idéntico formato y versión.
KEV_MIRROR_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
SOURCES_PATH = REPO_ROOT / "config" / "sources.yaml"

USER_AGENT = "vulnradar/0.3 (+https://github.com/nicoarias81/vulnradar)"
DEFAULT_POC_QUERY = "{cve_id}"

# CVE-YYYY-NNNN (4+ dígitos de secuencia).
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


# --------------------------------------------------------------------------
# KEV / EPSS
# --------------------------------------------------------------------------
def upsert_kev(conn, vulnerabilities) -> int:
    """
    Escribe SÓLO las columnas de KEV: un INSERT OR REPLACE borraría el EPSS
    ya cargado de la misma fila de enrichments.
    """
    count = 0
    for vuln in vulnerabilities:
        cve_id = (vuln.get("cveID") or "").strip()
        if not cve_id:
            continue
        # El FK exige el CVE padre; un stub mínimo evita perder la señal.
        ensure_cve_stub(conn, cve_id)
        conn.execute("""
            INSERT INTO enrichments (cve_id, in_kev, kev_date, ransomware_use)
            VALUES (?, 1, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                in_kev = 1,
                kev_date = excluded.kev_date,
                ransomware_use = excluded.ransomware_use,
                updated_at = CURRENT_TIMESTAMP
        """, (
            cve_id,
            vuln.get("dateAdded"),
            1 if vuln.get("knownRansomwareCampaignUse") == "Known" else 0,
        ))
        count += 1
    return count


EPSS_BATCH = 20_000

EPSS_UPSERT = """
    INSERT INTO enrichments (cve_id, epss, epss_percentile)
    VALUES (?, ?, ?)
    ON CONFLICT(cve_id) DO UPDATE SET
        epss = excluded.epss,
        epss_percentile = excluded.epss_percentile,
        updated_at = CURRENT_TIMESTAMP
"""


def upsert_epss(conn, rows) -> int:
    """Escribe SÓLO las columnas de EPSS, preservando KEV y el resto.

    El feed trae ~400k filas y antes iba en una única transacción: sostenía el
    lock sobre `cves` durante minutos y el `CREATE INDEX` del arranque del
    dashboard esperaba ese lock, así que el server no llegaba a abrir el puerto.
    Ahora va por lotes con commit y sólo crea stubs de los CVEs que faltan.
    """
    known = {row[0] for row in conn.execute("SELECT cve_id FROM cves").fetchall()}
    count = 0
    batch: list[tuple] = []
    for row in rows:
        cve_id = (row.get("cve") or "").strip()
        if not cve_id:
            continue
        if cve_id not in known:
            ensure_cve_stub(conn, cve_id)
            known.add(cve_id)
        batch.append((cve_id, _to_float(row.get("epss")), _to_float(row.get("percentile"))))
        if len(batch) >= EPSS_BATCH:
            conn.executemany(EPSS_UPSERT, batch)
            conn.commit()
            count += len(batch)
            batch = []
    if batch:
        conn.executemany(EPSS_UPSERT, batch)
        conn.commit()
        count += len(batch)
    return count


def load_kev(conn) -> int:
    last_error = None
    for url in (KEV_URL, KEV_MIRROR_URL):
        print(f"Downloading CISA KEV from {url}...")
        try:
            response = requests.get(url, timeout=60)
            if response.status_code != 200:
                raise RuntimeError(f"HTTP {response.status_code}")
            data = response.json()
            vulns = data.get("vulnerabilities") or []
            if not vulns:
                raise RuntimeError("JSON sin 'vulnerabilities'")
        except Exception as exc:  # 403/HTML de Akamai, red, JSON inválido
            last_error = exc
            print(f"KEV: fuente descartada ({type(exc).__name__}: {exc})")
            continue
        count = upsert_kev(conn, vulns)
        conn.commit()
        print(f"KEV loaded: {count} CVEs (catalog {data.get('catalogVersion', '?')}).")
        return count
    raise RuntimeError(f"KEV: ninguna fuente respondió ({last_error})")


def load_epss(conn) -> int:
    print("Downloading EPSS...")
    response = requests.get(EPSS_URL, timeout=60)
    with gzip.open(io.BytesIO(response.content), "rt", encoding="utf-8") as stream:
        # EPSS antepone metadatos ("#model_version:...,score_date:...") antes del header real.
        rows = (line for line in stream if line.strip() and not line.startswith("#"))
        count = upsert_epss(conn, csv.DictReader(rows))
    conn.commit()
    print(f"EPSS loaded: {count} CVEs.")
    return count


# --------------------------------------------------------------------------
# RSS: menciones de prensa
# --------------------------------------------------------------------------
def parse_feed(content, source=None) -> list:
    """Entradas de un feed RSS/Atom ya descargado. No toca la red."""
    parsed = feedparser.parse(content)
    feed_title = ""
    if parsed.feed:
        feed_title = (parsed.feed.get("title") or "").strip()

    entries = []
    for entry in parsed.entries:
        # Google News RSS pone el medio real en <source>: feed.title es la consulta.
        medio = entry.get("source")
        if isinstance(medio, dict):
            medio = medio.get("title") or ""
        entries.append({
            "url": (entry.get("link") or "").strip(),
            "title": (entry.get("title") or "").strip(),
            "summary": _strip_html(entry.get("summary") or entry.get("description") or ""),
            "published": _iso_date(entry),
            # El nombre del medio sale de la entrada; el feed y el host son fallback.
            "source": (medio or "").strip() or feed_title or source,
        })
    return entries


def collect_mentions(entries) -> list:
    """Explota cada entrada en menciones (cve_id, url). Un CVE por entrada."""
    mentions = []
    for entry in entries:
        haystack = " ".join(filter(None, [
            entry.get("title"), entry.get("summary"), entry.get("url"),
        ]))
        url = entry.get("url") or ""
        for cve_id in sorted({match.group(0).upper() for match in CVE_PATTERN.finditer(haystack)}):
            mentions.append({
                "cve_id": cve_id,
                # Sin link usable, la clave de dedupe es el propio CVE.
                "url": url or f"urn:cve:{cve_id}",
                "title": entry.get("title"),
                "source": entry.get("source"),
                "published": entry.get("published"),
            })
    return mentions


SEARCH_NEWS_URL = "https://news.google.com/rss/search?q={query}&hl=en-US&gl=US&ceid=US:en"


def search_mentions(cve_id, brand_name=None, *, session=None,
                    template=SEARCH_NEWS_URL, limit=25, timeout=20) -> list:
    """Menciones de prensa buscando el CVE (y su apodo) fuera de los feeds fijos.

    Los 7 feeds del ciclo sólo traen lo último publicado: un CVE que explotó hace
    dos semanas desaparece del radar aunque tenga 700 PoCs y esté en KEV. Esto
    levanta el historial completo desde la búsqueda de noticias.
    """
    http = session or requests.Session()
    queries = [cve_id] + ([brand_name.strip()] if brand_name and brand_name.strip() else [])
    vistas, salida = set(), []
    for query in queries:
        url = template.format(query=quote_plus(query))
        try:
            response = http.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()
        except Exception:
            continue
        for entry in parse_feed(response.content, source=f"news:{query}")[:limit]:
            clave = entry["url"]
            if not clave or clave in vistas:
                continue
            vistas.add(clave)
            entry["cve_id"] = cve_id
            salida.append(entry)
    return salida


HN_SEARCH_URL = "https://hn.algolia.com/api/v1/search"


def google_disponible(session=None, timeout=10) -> bool:
    """Google News responde 503 a IPs que ya hizo miles de consultas.

    Un probe por ciclo evita gastar 20 s de timeout por objetivo cuando la
    fuente está caída: si falla, el ciclo entero usa HN.
    """
    http = session or requests
    try:
        r = http.get(SEARCH_NEWS_URL.format(query="CVE-2024-3400"), timeout=timeout,
                     headers={"User-Agent": USER_AGENT})
        return r.status_code == 200
    except Exception:
        return False


def search_mentions_hn(cve_id, *, session=None, timeout=20, limit=30) -> list:
    """Menciones en Hacker News (Algolia). Sin key; ~30 req/min sostenidos.

    Alternativa a search_mentions cuando Google bloquea. Sólo stories: los
    comentarios mencionan CVEs al pasar y ensucian el conteo.
    """
    http = session or requests
    try:
        r = http.get(HN_SEARCH_URL, params={"query": cve_id, "hitsPerPage": limit},
                     timeout=timeout, headers={"User-Agent": USER_AGENT})
        if r.status_code != 200:
            return []
        hits = r.json().get("hits", [])
    except Exception:
        return []
    salida, vistas = [], set()
    for hit in hits:
        if "story" not in (hit.get("_tags") or []):
            continue
        titulo = (hit.get("title") or "").strip()
        url = (hit.get("url") or "").strip()
        if not titulo:
            continue
        if not url:
            url = f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
        if url in vistas:
            continue
        vistas.add(url)
        salida.append({
            "cve_id": cve_id,
            "url": url,
            "title": titulo,
            "source": "Hacker News",
            "published": hit.get("created_at"),
        })
    return salida


def load_attention(conn, limit=15, *, session=None) -> dict:
    """Busca prensa para los CVEs donde la atención importa (KEV/PoC/recientes).

    Google primero, HN como respaldo: en producción Google lleva bloqueado desde
    el primer día, así que HN es la fuente que realmente trae datos.
    """
    http = session or requests.Session()
    objetivos = select_attention_targets(conn, limit)
    if not objetivos:
        return {"objetivos": 0, "nuevas": 0, "google": 0, "hn": 0}
    usa_google = google_disponible(http)
    total = con_google = con_hn = 0
    for cve_id, brand_name in objetivos:
        menciones = search_mentions(cve_id, brand_name, session=http) if usa_google else []
        if menciones:
            con_google += 1
        else:
            menciones = search_mentions_hn(cve_id, session=http)
            if menciones:
                con_hn += 1
        nuevas = upsert_media_mentions(conn, menciones)
        total += sum(nuevas.values())
    return {"objetivos": len(objetivos), "nuevas": total,
            "google": con_google, "hn": con_hn}


def select_attention_targets(conn, limit=40) -> list:
    """CVEs donde la atención importa: con PoCs, en KEV o recientes.

    `cves.published` es TEXT ISO ('2026-10-31T10:11:47.188Z'): se compara como
    texto contra una fecha ISO, no casteando a timestamp (falla si viene vacío).
    """
    rows = conn.execute("""
        SELECT e.cve_id AS cve_id, e.brand_name AS brand_name
        FROM enrichments e
        LEFT JOIN cves c ON c.cve_id = e.cve_id
        WHERE COALESCE(e.poc_count, 0) > 0 OR COALESCE(e.in_kev, 0) = 1
           OR c.published >= to_char(CURRENT_TIMESTAMP - INTERVAL '60 days', 'YYYY-MM-DD')
        ORDER BY COALESCE(e.in_kev, 0) DESC, COALESCE(e.poc_count, 0) DESC,
                 c.published DESC
        LIMIT ?
    """, (max(0, int(limit)),)).fetchall()
    return [(row["cve_id"], row["brand_name"]) for row in rows]


def upsert_media_mentions(conn, mentions) -> dict:
    """
    Inserta menciones nuevas y suma media_count sólo por las nuevas.

    Devuelve {cve_id: menciones_nuevas}. La PK (cve_id, url) es el candado:
    una URL ya vista no vuelve a contar aunque el feed la republique.
    """
    nuevas: dict = {}
    for mention in mentions:
        cve_id = (mention.get("cve_id") or "").strip().upper()
        url = (mention.get("url") or "").strip()
        if not cve_id or not url:
            continue
        ensure_cve_stub(conn, cve_id)
        cursor = conn.execute("""
            INSERT INTO media_mentions (cve_id, url, title, source, published)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(cve_id, url) DO NOTHING
        """, (cve_id, url, mention.get("title"), mention.get("source"),
              mention.get("published")))
        if cursor.rowcount:  # 0 = URL ya vista: no se re-cuenta
            nuevas[cve_id] = nuevas.get(cve_id, 0) + 1

    for cve_id, delta in nuevas.items():
        conn.execute("""
            INSERT INTO enrichments (cve_id, media_count) VALUES (?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                media_count = COALESCE(enrichments.media_count, 0) + excluded.media_count,
                updated_at = CURRENT_TIMESTAMP
        """, (cve_id, delta))
    return nuevas


RERANK_SYSTEM = (
    "You extract structured facts from security news items. "
    "Reply with a JSON array only, no prose and no markdown fences."
)

RERANK_PROMPT = """\
For each security news item below, extract three fields.

cve_id: the CVE identifier the item is about (format CVE-YYYY-NNNN). Use the id
that appears in the text. If the text names no CVE, use null — do not guess.
brand_name: the marketing nickname the item itself uses for that vulnerability
(Log4Shell, Heartbleed, ShuffleShock, regreSSHion). Null when the text uses no
nickname; never invent one.
relevant: true only if the item is about a specific software vulnerability.
Events, policy, funding, opinion pieces and product launches are false.

Reply with a JSON array, one object per item, in the same order:
[{{"i": 1, "cve_id": null, "brand_name": null, "relevant": false}}]

Items:
{items}
"""

RERANK_BATCH = 6
RERANK_TITLE_CHARS = 160
RERANK_SUMMARY_CHARS = 180
# Tope por feed y corrida: el rerank es el paso caro (LLM), y los feeds
# republican decenas de notas viejas que no aportan menciones nuevas.
RERANK_MAX_ENTRIES = 40
# Advisories con CVE en el titular: no pasan por el modelo, pero un catálogo
# como el de MSRC trae miles de entradas y sólo interesa el tramo reciente.
REGEX_MAX_ENTRIES = 250


def build_rerank_prompt(entries) -> str:
    lines = []
    for index, entry in enumerate(entries, 1):
        title = (entry.get("title") or "").replace('"', "'")[:RERANK_TITLE_CHARS]
        summary = (entry.get("summary") or "").replace('"', "'")[:RERANK_SUMMARY_CHARS]
        lines.append(f'{index}. title="{title}" summary="{summary}"')
    return RERANK_PROMPT.format(items="\n".join(lines))


def parse_rerank_reply(reply) -> list:
    """Saca el array JSON de la respuesta, tolerando fences o prosa alrededor."""
    text = (reply or "").strip()
    if not text:
        return []
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end <= start:
        return []
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        return []
    return [item for item in data if isinstance(item, dict)]


def rerank_entries(entries, *, config=None, completer=None, batch_size=RERANK_BATCH) -> list:
    """Pasa las entradas por el LLM y devuelve {cve_id, brand_name, relevant}.

    Mismo orden que `entries`. Si el LLM falla en un lote, esas entradas quedan
    sin rerank (cve_id None) y el llamador decide: no se pierde el feed.
    """
    call = completer or (lambda prompt: llm_client.complete(
        prompt, system=RERANK_SYSTEM, config=config))
    out: list = [{} for _ in entries]
    for start in range(0, len(entries), batch_size):
        chunk = entries[start:start + batch_size]
        try:
            reply = call(build_rerank_prompt(chunk))
        except Exception as exc:  # LLM caído no debe tumbar el enrich
            print(f"rerank: {type(exc).__name__}: {str(exc)[:120]}")
            continue
        for item in parse_rerank_reply(reply):
            index = item.get("i")
            if not isinstance(index, int) or not 1 <= index <= len(chunk):
                continue
            cve_id = str(item.get("cve_id") or "").strip().upper() or None
            if cve_id and not CVE_PATTERN.fullmatch(cve_id):
                cve_id = None
            brand = str(item.get("brand_name") or "").strip() or None
            # Un apodo sin CVE no se puede colgar de ninguna fila.
            if brand and len(brand) > 48:
                brand = None
            out[start + index - 1] = {
                "cve_id": cve_id,
                "brand_name": brand if cve_id else None,
                "relevant": bool(item.get("relevant")),
            }
    return out


RERANK_URL_TTL_DAYS = 45


def _reranked_urls(conn, entries) -> set:
    """URLs que ya pasaron por el rerank dentro de la ventana de retención."""
    urls = [e.get("url") for e in entries if e.get("url")]
    if not urls:
        return set()
    try:
        rows = conn.execute(
            "SELECT url FROM reranked_urls WHERE url = ANY(?) "
            "AND reranked_at > CURRENT_TIMESTAMP - INTERVAL '%d days'"
            % RERANK_URL_TTL_DAYS,
            (urls,),
        ).fetchall()
    except Exception:
        return set()  # base sin la tabla (schema viejo): se reprocesa, no se rompe
    return {row["url"] for row in rows}


def _mark_reranked(conn, entries, reranked) -> None:
    """Registra sólo las entradas que el LLM contestó: los lotes caídos se reintentan."""
    try:
        for entry, verdict in zip(entries, reranked):
            url = entry.get("url")
            if not url or not verdict:
                continue
            conn.execute(
                "INSERT INTO reranked_urls (url) VALUES (?) ON CONFLICT (url) DO NOTHING",
                (url,),
            )
    except Exception:
        pass


def mentions_from_rerank(entries, reranked) -> list:
    """Menciones a partir del rerank; las que no son de una vuln se descartan."""
    mentions = []
    for entry, verdict in zip(entries, reranked):
        if not verdict or verdict.get("relevant") is False:
            continue
        cve_id = verdict.get("cve_id")
        if not cve_id:
            continue
        url = entry.get("url") or ""
        mentions.append({
            "cve_id": cve_id,
            "url": url or f"urn:cve:{cve_id}",
            "title": entry.get("title"),
            "source": entry.get("source"),
            "published": entry.get("published"),
            "brand_name": verdict.get("brand_name"),
        })
    return mentions


def load_rss(conn, feeds, *, session=None, timeout=30, rerank=False,
             config=None, completer=None, regex_feeds=None) -> dict:
    """Descarga los feeds y acumula menciones. Un feed caído no corta el resto.

    Con `rerank` cada entrada pasa por el LLM: descarta lo que no es una
    vulnerabilidad concreta, resuelve el CVE del texto y, cuando el titular usa
    un apodo (Log4Shell), lo guarda como brand_name del CVE.

    `regex_feeds` son los que ya traen el CVE en el titular (advisories de
    vendor y CERT): ahí el regex alcanza. Van sin LLM y sin el tope de 40, que
    en un catálogo de miles siempre deja entrar los mismos 40 y nunca los
    nuevos.
    """
    http = session or requests
    regex_set = set(regex_feeds or ())
    nuevas: dict = {}
    for url in feeds or []:
        try:
            response = http.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()
            content = getattr(response, "content", None) or response.text
        except Exception as exc:
            print(f"RSS {url}: {exc}")
            continue
        entries = parse_feed(content, source=_host(url))
        if rerank and url not in regex_set:
            entries = entries[:RERANK_MAX_ENTRIES]
            # Los RSS rotan lento: lo ya rerankeado no se vuelve a mandar al LLM
            # (medido: ~5 min de modelo por ciclo para 0 menciones nuevas).
            known = _reranked_urls(conn, entries)
            fresh = [e for e in entries if (e.get("url") or "") not in known]
            if fresh:
                reranked = rerank_entries(fresh, config=config, completer=completer)
                mentions = mentions_from_rerank(fresh, reranked)
                _mark_reranked(conn, fresh, reranked)
            else:
                mentions = []
        else:
            # Los catálogos vienen de más nuevo a más viejo: el tope deja el
            # tramo reciente y el upsert se encarga del resto.
            mentions = collect_mentions(entries[:REGEX_MAX_ENTRIES])
        for cve_id, delta in upsert_media_mentions(conn, mentions).items():
            nuevas[cve_id] = nuevas.get(cve_id, 0) + delta
        apply_mention_brands(conn, mentions)
    return nuevas


def apply_mention_brands(conn, mentions) -> int:
    """Escribe en enrichments el apodo que el titular usa para el CVE.

    El apodo sólo se acepta desde la prensa: es el único lugar donde aparece.
    """
    written = 0
    for mention in mentions:
        brand = (mention.get("brand_name") or "").strip()
        cve_id = (mention.get("cve_id") or "").strip().upper()
        if not brand or not cve_id:
            continue
        current = conn.execute(
            "SELECT brand_name FROM enrichments WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if current and (current["brand_name"] or "").strip():
            continue  # no se pisa un apodo ya establecido
        ensure_cve_stub(conn, cve_id)
        conn.execute("""
            INSERT INTO enrichments (cve_id, branding, brand_name) VALUES (?, 1, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                branding = 1, brand_name = excluded.brand_name,
                updated_at = CURRENT_TIMESTAMP
        """, (cve_id, brand))
        written += 1
    return written


# --------------------------------------------------------------------------
# GitHub: PoCs
# --------------------------------------------------------------------------
def build_poc_query(template, cve_id) -> str:
    """Renderiza el template de sources.yaml y le agrega `poc` si falta."""
    rendered = (template or DEFAULT_POC_QUERY).format(cve_id=cve_id).strip()
    return rendered if "poc" in rendered.lower() else f"{rendered} poc"


def fetch_poc_repos(cve_id, *, session=None, token=None, template=DEFAULT_POC_QUERY,
                    timeout=20, per_page=30) -> tuple:
    """(total en GitHub, repos con métricas). Una llamada sirve para contar y listar."""
    http = session or requests
    resolved_token = os.getenv("GITHUB_TOKEN") if token is None else token
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    if resolved_token:
        headers["Authorization"] = f"Bearer {resolved_token}"

    params = {
        "q": build_poc_query(template, cve_id),
        "per_page": max(1, int(per_page)),
        "sort": "stars",
        "order": "desc",
    }
    try:
        response = http.get(GITHUB_SEARCH_URL, params=params, headers=headers, timeout=timeout)
        response.raise_for_status()
        data = response.json() or {}
    except Exception as exc:
        print(f"GitHub {cve_id}: {exc}")
        return 0, []

    total = data.get("total_count")
    if total is None:
        total = len(data.get("items") or [])
    try:
        total = max(0, int(total))
    except (TypeError, ValueError):
        total = 0

    repos = []
    for item in data.get("items") or []:
        nombre = (item.get("full_name") or "").strip()
        if not nombre:
            continue
        repos.append({
            "repo": nombre,
            "url": item.get("html_url") or f"https://github.com/{nombre}",
            "stars": int(item.get("stargazers_count") or 0),
            "forks": int(item.get("forks_count") or 0),
            "language": item.get("language"),
            "pushed_at": item.get("pushed_at"),
            "created_at": item.get("created_at"),
        })
    return total, repos


def upsert_pocs(conn, cve_id, repos) -> int:
    """Guarda los repos con sus métricas: se refrescan en cada pasada."""
    guardados = 0
    for repo in repos or []:
        nombre = (repo.get("repo") or "").strip()
        if not nombre:
            continue
        conn.execute(
            """
            INSERT INTO pocs (cve_id, repo, url, stars, forks, language, pushed_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (cve_id, repo) DO UPDATE SET
                url = EXCLUDED.url,
                stars = EXCLUDED.stars,
                forks = EXCLUDED.forks,
                language = EXCLUDED.language,
                pushed_at = EXCLUDED.pushed_at,
                seen_at = CURRENT_TIMESTAMP
            """,
            (
                cve_id, nombre, repo.get("url") or f"https://github.com/{nombre}",
                int(repo.get("stars") or 0), int(repo.get("forks") or 0),
                repo.get("language"), repo.get("pushed_at"), repo.get("created_at"),
            ),
        )
        guardados += 1
    return guardados


def fetch_poc_count(cve_id, *, session=None, token=None, template=DEFAULT_POC_QUERY,
                    timeout=20) -> int:
    """
    Cuenta repos que probablemente son PoC. Sin GITHUB_TOKEN la API puede
    devolver 403 por rate limit: se loguea y se sigue con 0.
    """
    total, _ = fetch_poc_repos(
        cve_id, session=session, token=token, template=template, timeout=timeout,
        per_page=1,
    )
    return total


def upsert_poc_count(conn, cve_id, count) -> None:
    """Reemplaza poc_count: la búsqueda es la verdad, no se suma a ciegas."""
    cve_id = (cve_id or "").strip().upper()
    if not cve_id:
        return
    ensure_cve_stub(conn, cve_id)
    conn.execute("""
        INSERT INTO enrichments (cve_id, poc_count) VALUES (?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            poc_count = excluded.poc_count,
            updated_at = CURRENT_TIMESTAMP
    """, (cve_id, max(0, int(count or 0))))


def select_poc_targets(conn, limit=25) -> list:
    """Lote acotado: primero los CVEs con prensa, después los más recientes."""
    rows = conn.execute("""
        SELECT e.cve_id AS cve_id
        FROM enrichments e
        LEFT JOIN cves c ON c.cve_id = e.cve_id
        ORDER BY (e.media_count > 0) DESC, e.media_count DESC, c.published DESC
        LIMIT ?
    """, (max(0, int(limit)),)).fetchall()
    return [row["cve_id"] for row in rows]


def load_pocs(conn, cve_ids, *, session=None, token=None,
              template=DEFAULT_POC_QUERY) -> int:
    count = 0
    for cve_id in cve_ids or []:
        total, repos = fetch_poc_repos(
            cve_id, session=session, token=token, template=template,
        )
        upsert_poc_count(conn, cve_id, total)
        upsert_pocs(conn, cve_id, repos)
        count += 1
    return count


# --------------------------------------------------------------------------
# Branding + tone_score (LLM con fallback heurístico)
# --------------------------------------------------------------------------
TONE_SYSTEM = (
    "You are a security-news hype analyst. You answer with JSON only, no prose."
)

TONE_MIN, TONE_MAX = 0.0, 10.0

# Señales del fallback heurístico (el LLM es el camino principal).
PANIC_CUES = (
    "apocalyp", "catastroph", "chaos", "devastat", "nightmare", "massive",
    "critical", "severe", "under attack", "wormable", "zero-day", "0day",
    "exploited in the wild", "emergency",
)
CALM_CUES = (
    "advisory", "patch", "mitigat", "coordinated disclosure", "routine",
    "low severity",
)
# Nombres de exploit conocidos: el heurístico no puede adivinar todos.
KNOWN_BRANDS = (
    "Log4Shell", "Spring4Shell", "Heartbleed", "Shellshock", "RegreSSHion",
    "Dirty Pipe", "Dirty COW", "BlueKeep", "EternalBlue", "Pwn2Own",
)
BRAND_CUES = ("named", "dubbed", "christened", "nicknamed", "called")
# Token con mayúsculas adentro: Log4Shell, Pwn2Own (CVE o HTTP quedan afuera).
MIXED_CASE_TOKEN = re.compile(r"\b[A-Za-z0-9][A-Za-z0-9]*[A-Z][A-Za-z0-9]*\b")
NAMED_BRAND = re.compile(
    r"(?:named|dubbed|christened|nicknamed|called)\s+[\"“']?([A-Z][\w.-]{2,})"
)


def build_tone_prompt(items) -> str:
    lines = [
        "Rate each CVE headline on two dimensions.",
        "",
        "tone_score: integer 0-10. 0 = dry technical advisory, 10 = panic or clickbait.",
        "branding: true only if the text gives the vulnerability a marketing name",
        "(examples: Log4Shell, Heartbleed, Shellshock, RegreSSHion).",
        "brand_name: that exact name when branding is true, otherwise null.",
        "",
        'Reply with a JSON array, one object per headline:',
        '[{"cve_id": "...", "tone_score": 0, "branding": false, "brand_name": null}]',
        "",
        "Headlines:",
    ]
    for item in items:
        lines.append(f'- cve_id={item["cve_id"]} headline={item.get("title") or ""}')
    return "\n".join(lines)


def heuristic_tone(title) -> float:
    """0 = seco/técnico, 10 = pánico. Signos de exclamación + palabras."""
    text = (title or "").lower()
    score = 3.0
    panic = sum(1 for cue in PANIC_CUES if cue in text)
    calm = sum(1 for cue in CALM_CUES if cue in text)
    score += min(6.0, 2.0 * panic)
    score += min(3.0, float(text.count("!")))
    score -= min(4.0, 2.0 * calm)
    return round(max(TONE_MIN, min(TONE_MAX, score)), 1)


def heuristic_branding(text) -> tuple:
    """(branding, brand_name) por nombre conocido, CamelCase o 'dubbed X'."""
    raw = text or ""

    lowered = raw.lower()
    for brand in KNOWN_BRANDS:
        if brand.lower() in lowered:
            return True, brand

    for token in MIXED_CASE_TOKEN.findall(raw):
        if _looks_like_brand(token):
            return True, token

    named = NAMED_BRAND.search(raw)
    if named:
        return True, named.group(1)

    return False, None


def analyze_tone_batch(items, *, completer=None, config=None, session=None) -> list:
    """
    Una sola llamada al LLM por lote. Si el modelo falla o devuelve JSON roto,
    cada ítem cae al heurístico (la fila nunca queda sin tone_score).
    """
    batch = [item for item in items or [] if (item.get("cve_id") or "").strip()]
    if not batch:
        return []

    answered: dict = {}
    try:
        llm = completer or llm_client.complete
        text = llm(
            build_tone_prompt(batch),
            system=TONE_SYSTEM,
            config=config,
            session=session,
        )
        for entry in _parse_tone_response(text):
            cve_id = (entry.get("cve_id") or "").strip().upper()
            if cve_id:
                answered[cve_id] = entry
    except Exception as exc:
        print(f"LLM: {exc}. Falling back to the heuristic.")

    results = []
    for item in batch:
        cve_id = item["cve_id"].strip().upper()
        title = item.get("title") or ""
        entry = answered.get(cve_id)
        tone = _to_tone(entry.get("tone_score")) if entry else None
        if tone is None:
            # Sin respuesta del modelo (o sin tone_score usable) manda el heurístico.
            branding, brand_name = heuristic_branding(title)
            results.append({
                "cve_id": cve_id,
                "tone_score": heuristic_tone(title),
                "branding": branding,
                "brand_name": brand_name,
                "source": "heuristic",
            })
            continue
        branding = _as_bool(entry.get("branding"))
        results.append({
            "cve_id": cve_id,
            "tone_score": tone,
            "branding": branding,
            "brand_name": _as_text(entry.get("brand_name")) if branding else None,
            "source": "llm",
        })
    return results


def upsert_tone(conn, results) -> int:
    """Escribe SÓLO tone_score/branding/brand_name: KEV y EPSS quedan intactos."""
    count = 0
    for result in results or []:
        cve_id = (result.get("cve_id") or "").strip().upper()
        tone = _to_tone(result.get("tone_score"))
        if not cve_id or tone is None:
            continue  # sin tone usable no se escribe: huele a dato inventado
        ensure_cve_stub(conn, cve_id)
        conn.execute("""
            INSERT INTO enrichments (cve_id, tone_score, branding, brand_name)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                tone_score = excluded.tone_score,
                branding = excluded.branding,
                brand_name = excluded.brand_name,
                updated_at = CURRENT_TIMESTAMP
        """, (
            cve_id,
            tone,
            1 if result.get("branding") else 0,
            _as_text(result.get("brand_name")),
        ))
        count += 1
    return count


def select_tone_targets(conn, limit=50) -> list:
    """Titulares a analizar: primero los CVEs que nunca tuvieron tone_score."""
    rows = conn.execute("""
        SELECT m.cve_id AS cve_id, m.title AS title, e.tone_score AS tone_score
        FROM media_mentions m
        LEFT JOIN enrichments e ON e.cve_id = m.cve_id
        WHERE m.title IS NOT NULL AND m.title <> ''
        ORDER BY (e.tone_score IS NOT NULL), m.id DESC
    """).fetchall()

    targets, seen = [], set()
    for row in rows:
        cve_id = row["cve_id"]
        if cve_id in seen:
            continue
        seen.add(cve_id)
        targets.append({"cve_id": cve_id, "title": row["title"]})
        if len(targets) >= max(0, int(limit)):
            break
    return targets


def load_tone(conn, *, limit=50, batch_size=10, completer=None, config=None,
              session=None) -> int:
    """Un lote = una llamada. Default 10 titulares por lote."""
    targets = select_tone_targets(conn, limit)
    size = max(1, int(batch_size))
    updated = 0
    for start in range(0, len(targets), size):
        chunk = targets[start:start + size]
        updated += upsert_tone(conn, analyze_tone_batch(
            chunk, completer=completer, config=config, session=session,
        ))
    return updated


# --------------------------------------------------------------------------
# Config, orquestación y CLI
# --------------------------------------------------------------------------
def load_sources_config(path=None) -> dict:
    """Bloque `sources:` de config/sources.yaml (o {} si no existe)."""
    source_path = Path(path) if path else SOURCES_PATH
    if not source_path.exists():
        return {}
    data = yaml.safe_load(source_path.read_text(encoding="utf-8")) or {}
    sources = data.get("sources") if isinstance(data, dict) else None
    return sources if isinstance(sources, dict) else {}


def run(*, skip_kev=False, skip_epss=False, skip_rss=False, skip_github=False,
        skip_llm=False, skip_attention=False, db_path=None, sources_path=None,
        github_limit=25, llm_limit=50, llm_batch_size=10, session=None,
        completer=None) -> dict:
    """Corre las seis señales en orden y devuelve un resumen de conteos."""
    sources = load_sources_config(sources_path)
    path = init_db(db_path)  # idempotente: crea media_mentions si falta
    conn = get_db(path)
    summary = {"kev": 0, "epss": 0, "rss": {}, "poc": 0, "tone": 0, "attention": {}}
    try:
        if not skip_kev:
            summary["kev"] = load_kev(conn)
        if not skip_epss:
            summary["epss"] = load_epss(conn)

        if not skip_rss:
            summary["rss"] = load_rss(
                conn, sources.get("rss") or [], session=session,
                rerank=bool(sources.get("rerank_feeds")), completer=None,
                regex_feeds=sources.get("rss_regex_only") or [],
            )

        github_cfg = sources.get("github_search") or {}
        if not skip_github and github_cfg.get("enabled"):
            summary["poc"] = load_pocs(
                conn,
                select_poc_targets(conn, github_limit),
                session=session,
                template=github_cfg.get("query_template") or DEFAULT_POC_QUERY,
            )

        if not skip_llm:
            summary["tone"] = load_tone(
                conn, limit=llm_limit, batch_size=llm_batch_size,
                completer=completer,
            )

        attention_cfg = sources.get("attention") or {}
        if not skip_attention and attention_cfg.get("enabled", True):
            summary["attention"] = load_attention(
                conn, int(attention_cfg.get("limit", 15)), session=session,
            )
        conn.commit()
    finally:
        conn.close()
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Enrichment de CVEs: KEV, EPSS, RSS, PoCs en GitHub y tone/branding.",
    )
    parser.add_argument("--skip-kev", action="store_true", help="No descarga CISA KEV.")
    parser.add_argument("--skip-epss", action="store_true", help="No descarga FIRST EPSS.")
    parser.add_argument("--skip-rss", action="store_true", help="No lee los feeds RSS.")
    parser.add_argument("--skip-github", action="store_true", help="No busca PoCs en GitHub.")
    parser.add_argument("--skip-llm", action="store_true", help="No llama al LLM (no escribe tone/branding).")
    parser.add_argument("--skip-attention", action="store_true",
                        help="No busca prensa de los CVEs con KEV/PoC/recencia (Google + HN).")
    parser.add_argument("--rss-only", action="store_true", help="Sólo RSS (local): implica los demás --skip-*.")
    parser.add_argument("--github-limit", type=int, default=25, help="CVEs a buscar en GitHub (default 25).")
    parser.add_argument("--llm-limit", type=int, default=50, help="CVEs a analizar con el LLM (default 50).")
    parser.add_argument("--llm-batch-size", type=int, default=10, help="Titulares por llamada (default 10).")
    parser.add_argument("--sources", default=None, help="Ruta a sources.yaml (default config/sources.yaml).")
    parser.add_argument("--db-path", default=None, help="Schema de test. Producción: DATABASE_URL.")
    parser.add_argument("--llm-smoke", action="store_true", help="Una llamada real al LLM y sale.")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.llm_smoke:
        return _llm_smoke()

    summary = run(
        skip_kev=args.skip_kev or args.rss_only,
        skip_epss=args.skip_epss or args.rss_only,
        skip_rss=args.skip_rss,
        skip_github=args.skip_github or args.rss_only,
        skip_llm=args.skip_llm or args.rss_only,
        skip_attention=args.skip_attention or args.rss_only,
        db_path=args.db_path,
        sources_path=args.sources,
        github_limit=args.github_limit,
        llm_limit=args.llm_limit,
        llm_batch_size=args.llm_batch_size,
    )
    att = summary.get("attention") or {}
    print(
        f"Enrichment listo: kev={summary['kev']} epss={summary['epss']} "
        f"rss_cves={len(summary['rss'])} "
        f"rss_menciones_nuevas={sum(summary['rss'].values())} "
        f"poc_cves={summary['poc']} tone_cves={summary['tone']} "
        f"attention={att.get('objetivos', 0)}obj/{att.get('nuevas', 0)}nuevas"
    )
    return 0


def _llm_smoke() -> int:
    """Humo en vivo: una sola llamada real. Nunca imprime la API key."""
    cfg = llm_client.load_llm_config()
    print(f"provider={cfg.provider} model={cfg.model} base_url={cfg.base_url}")
    sample = [{
        "cve_id": "CVE-2021-44228",
        "title": "Log4Shell apocalypse!!! Critical RCE under active attack",
    }]
    for result in analyze_tone_batch(sample):
        print(result)
    return 0


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _parse_tone_response(text) -> list:
    """Acepta un objeto o un array, con o sin ```json ... ``` alrededor."""
    raw = (text or "").strip()
    if not raw:
        raise ValueError("respuesta LLM vacía")

    fenced = re.search(r"```(?:json)?\s*(.+?)```", raw, re.DOTALL)
    if fenced:
        raw = fenced.group(1).strip()

    starts = [index for index in (raw.find("["), raw.find("{")) if index >= 0]
    if not starts:
        raise ValueError("respuesta LLM sin JSON")
    payload, _ = json.JSONDecoder().raw_decode(raw[min(starts):])

    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    raise ValueError("respuesta LLM con JSON inesperado")


def _looks_like_brand(token: str) -> bool:
    """FooShell sí; CVE, HTTP o 2026 no."""
    if len(token) < 5:
        return False
    if any(char.isdigit() for char in token) and any(char.isalpha() for char in token):
        return True
    return any(char.islower() for char in token) and any(char.isupper() for char in token[1:])


def _strip_html(value) -> str:
    return re.sub(r"<[^>]+>", " ", str(value or "")).strip()


def _iso_date(entry) -> str | None:
    """Fecha del feed en ISO 8601 UTC; si no se puede parsear, el texto crudo."""
    stamp = entry.get("published_parsed") or entry.get("updated_parsed")
    if not stamp:
        return entry.get("published") or entry.get("updated")
    return datetime(*stamp[:6], tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _host(url: str) -> str:
    match = re.match(r"https?://([^/]+)", url or "")
    return match.group(1) if match else ""


def _to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _to_tone(value):
    """tone_score acotado a 0-10, o None si el valor no es numérico."""
    number = _to_float(value)
    if number is None:
        return None
    return round(max(TONE_MIN, min(TONE_MAX, number)), 1)


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in ("1", "true", "yes", "si", "sí")


def _as_text(value):
    if value is None:
        return None
    text = str(value).strip()
    return text or None


if __name__ == "__main__":
    raise SystemExit(main())
