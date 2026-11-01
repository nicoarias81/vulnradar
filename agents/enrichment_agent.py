"""
Enrichment Agent — per-CVE signals: KEV, EPSS, media (RSS), PoCs (GitHub)
and branding/tone_score (LLM).

Usage:
    python agents/enrichment_agent.py                 # run everything
    python agents/enrichment_agent.py --rss-only      # RSS only (local)
    python agents/enrichment_agent.py --skip-llm      # no LLM calls
    python agents/enrichment_agent.py --llm-smoke     # 1 real call and exit

Every source writes ONLY its own columns: an INSERT OR REPLACE would wipe the
rest of the enrichments row. Tests have no network: the network functions take
`session` and the LLM step takes an injectable `completer`.
"""
import argparse
import csv
import gzip
import io
import json
import hashlib
from html import unescape
import math
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_plus, urlsplit, urlunsplit, parse_qsl, urlencode

import feedparser
import requests
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import llm as llm_client
from core.db import REPO_ROOT, ensure_cve_stub, get_db, init_db
from core.evidence import observe, record_run, run_source, source_poc_count

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# cisa.gov answers 403 "Access Denied" (Akamai) to datacenter IPs: the official
# kev-data repo publishes the same catalog in JSON, same format and version.
KEV_MIRROR_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
SOURCES_PATH = REPO_ROOT / "config" / "sources.yaml"

USER_AGENT = "vulnradar/0.3 (+https://github.com/nicoarias81/vulnradar)"
DEFAULT_POC_QUERY = "{cve_id}"

# CVE-YYYY-NNNN (sequence of 4+ digits).
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


# --------------------------------------------------------------------------
# KEV / EPSS
# --------------------------------------------------------------------------
def upsert_kev(conn, vulnerabilities) -> int:
    """
    Writes ONLY the KEV columns: an INSERT OR REPLACE would wipe the EPSS
    already loaded on the same enrichments row.
    """
    count = 0
    for vuln in vulnerabilities:
        cve_id = (vuln.get("cveID") or "").strip()
        if not cve_id:
            continue
        # The FK needs the parent CVE; a minimal stub keeps the signal from being lost.
        ensure_cve_stub(conn, cve_id)
        observe(conn, cve_id, 'cisa-kev', 'exploited', cve_id,
                event_date=vuln.get('dateAdded'), trusted=True, payload=vuln)
        conn.execute("""
            INSERT INTO enrichments (cve_id, in_kev, kev_date, ransomware_use, kev_checked_at)
            VALUES (?, 1, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(cve_id) DO UPDATE SET
                in_kev = 1,
                kev_date = excluded.kev_date,
                ransomware_use = excluded.ransomware_use,
                kev_checked_at = CURRENT_TIMESTAMP,
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
    INSERT INTO enrichments (cve_id, epss, epss_percentile, epss_date, epss_model)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(cve_id) DO UPDATE SET
        epss = excluded.epss,
        epss_percentile = excluded.epss_percentile,
        epss_date = excluded.epss_date,
        epss_model = excluded.epss_model,
        updated_at = CURRENT_TIMESTAMP
"""


def upsert_epss(conn, rows, *, score_date=None, model_version=None) -> int:
    """Writes ONLY the EPSS columns, preserving KEV and the rest.

    The feed carries ~400k rows and used to run in a single transaction: it held
    the lock on `cves` for minutes and the `CREATE INDEX` on dashboard startup
    waited on that lock, so the server never got as far as opening the port.
    It now goes in batches with a commit and only stubs the CVEs that are missing.
    """
    known = {row[0] for row in conn.execute("SELECT cve_id FROM cves").fetchall()}
    count = 0
    batch: list[tuple] = []
    for row in rows:
        cve_id = (row.get("cve") or "").strip()
        epss, percentile = _to_float(row.get('epss')), _to_float(row.get('percentile'))
        if not CVE_PATTERN.fullmatch(cve_id) or epss is None or not 0 <= epss <= 1:
            continue
        if percentile is not None and not 0 <= percentile <= 1:
            percentile = None
        if cve_id not in known:
            ensure_cve_stub(conn, cve_id)
            known.add(cve_id)
        batch.append((cve_id, epss, percentile, score_date or datetime.now(timezone.utc).date().isoformat(), model_version or 'unspecified'))
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
    configured = (load_sources_config().get('kev') or {}).get('url') or KEV_URL
    for url in dict.fromkeys((configured, KEV_MIRROR_URL)):
        print(f"Downloading CISA KEV from {url}...")
        try:
            response = requests.get(url, timeout=60)
            if response.status_code != 200:
                raise RuntimeError(f"HTTP {response.status_code}")
            data = response.json()
            vulns = data.get("vulnerabilities") or []
            if not vulns:
                raise RuntimeError("JSON without 'vulnerabilities'")
        except Exception as exc:  # Akamai 403/HTML, network, invalid JSON
            last_error = exc
            print(f"KEV: fuente descartada ({type(exc).__name__}: {exc})")
            continue
        count = upsert_kev(conn, vulns)
        ids = [v.get('cveID') for v in vulns if CVE_PATTERN.fullmatch(v.get('cveID') or '')]
        if len(ids) != len(vulns):
            raise ValueError('Incomplete or invalid KEV snapshot')
        conn.execute("UPDATE enrichments SET in_kev=0, ransomware_use=0, kev_checked_at=CURRENT_TIMESTAMP WHERE in_kev=1 AND NOT (cve_id = ANY(?))", (ids,))
        conn.execute("UPDATE evidence SET active=false WHERE source='cisa-kev' AND NOT (cve_id = ANY(?))", (ids,))
        record_run(conn, 'cisa-kev', 'SUCCESS', {'count':count, 'url':url}, data.get('catalogVersion'))
        conn.commit()
        print(f"KEV loaded: {count} CVEs (catalog {data.get('catalogVersion', '?')}).")
        return count
    raise RuntimeError(f"KEV: no source responded ({last_error})")


def load_epss(conn) -> int:
    print("Downloading EPSS...")
    url = (load_sources_config().get('epss') or {}).get('url') or EPSS_URL
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    with gzip.open(io.BytesIO(response.content), "rt", encoding="utf-8") as stream:
        # EPSS prepends metadata ("#model_version:...,score_date:...") before the real header.
        metadata = stream.readline().strip()
        match = re.search(r'model_version:([^,]+),score_date:([^,]+)', metadata)
        if not match:
            raise ValueError('EPSS snapshot lacks model/date metadata')
        model, date = match.groups()
        rows = (line for line in stream if line.strip() and not line.startswith("#"))
        count = upsert_epss(conn, csv.DictReader(rows), score_date=date, model_version=model)
        if not count:
            raise ValueError('Empty EPSS snapshot')
        record_run(conn, 'epss', 'SUCCESS', {'count':count,'score_date':date}, model)
    conn.commit()
    print(f"EPSS loaded: {count} CVEs.")
    return count


# --------------------------------------------------------------------------
# RSS: press mentions
# --------------------------------------------------------------------------
def parse_feed(content, source=None) -> list:
    """Entries of an already downloaded RSS/Atom feed. Does not touch the network."""
    parsed = feedparser.parse(content)
    feed_title = ""
    if parsed.feed:
        feed_title = (parsed.feed.get("title") or "").strip()

    entries = []
    for entry in parsed.entries:
        # Atom/content:encoded can contain the CVEs absent from the lead summary.
        # Retain identifiers only; do not persist or republish the article body.
        body = ' '.join(str(part.get('value') or '') for part in (entry.get('content') or []) if isinstance(part, dict))
        explicit_text = ' '.join(_strip_html(entry.get(k) or '') for k in ('title','summary','description')) + ' ' + str(entry.get('link') or '') + ' ' + _strip_html(body)
        cve_ids = sorted({m.group(0).upper() for m in CVE_PATTERN.finditer(explicit_text)})
        # Google News RSS puts the real outlet in <source>: feed.title is the query.
        medio = entry.get("source")
        if isinstance(medio, dict):
            medio = medio.get("title") or ""
        entries.append({
            "url": (entry.get("link") or "").strip(),
            "title": (entry.get("title") or "").strip(),
            "summary": _strip_html(entry.get("summary") or entry.get("description") or ""),
            "published": _iso_date(entry),
            # The outlet name comes from the entry; feed and host are the fallback.
            "source": (medio or "").strip() or feed_title or source,
            "cve_ids": cve_ids,
        })
    return entries


def entry_cve_ids(entry):
    text = ' '.join(str(entry.get(k) or '') for k in ('title','summary','url'))
    ids = {m.group(0).upper() for m in CVE_PATTERN.finditer(text)}
    ids.update(str(c).upper() for c in (entry.get('cve_ids') or []) if CVE_PATTERN.fullmatch(str(c)))
    return ids


def collect_mentions(entries) -> list:
    """Expands each entry into mentions (cve_id, url). One CVE per entry."""
    mentions = []
    for entry in entries:
        url = entry.get("url") or ""
        for cve_id in sorted(entry_cve_ids(entry)):
            mentions.append({
                "cve_id": cve_id,
                # With no usable link, the dedupe key is the CVE itself.
                "url": url or f"urn:cve:{cve_id}",
                "title": entry.get("title"),
                "source": entry.get("source"),
                "published": entry.get("published"),
            })
    return mentions


SEARCH_NEWS_URL = "https://news.google.com/rss/search?q={query}&hl=en-US&gl=US&ceid=US:en"


def search_mentions(cve_id, brand_name=None, *, session=None,
                    template=SEARCH_NEWS_URL, limit=25, timeout=20) -> list:
    """Press mentions searching the CVE (and its nickname) beyond the fixed feeds.

    The cycle's 7 feeds only carry the latest published items: a CVE exploited
    two weeks ago drops off the radar even with 700 PoCs and KEV membership.
    This pulls the full history from news search.
    """
    http = session or requests.Session()
    queries = [cve_id] + ([brand_name.strip()] if brand_name and brand_name.strip() else [])
    seen_urls, chunks = set(), []
    for query in queries:
        url = template.format(query=quote_plus(query))
        try:
            response = http.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()
        except Exception:
            continue
        for entry in parse_feed(response.content, source=f"news:{query}")[:limit]:
            clave = entry["url"]
            if not clave or clave in seen_urls:
                continue
            seen_urls.add(clave)
            entry["cve_id"] = cve_id
            chunks.append(entry)
    return chunks


HN_SEARCH_URL = "https://hn.algolia.com/api/v1/search"


def google_disponible(session=None, timeout=10) -> bool:
    """Google News answers 503 to IPs that already made thousands of queries.

    One probe per cycle avoids burning a 20 s timeout per target when the source
    is down: if it fails, the whole cycle uses HN.
    """
    http = session or requests
    try:
        r = http.get(SEARCH_NEWS_URL.format(query="CVE-2024-3400"), timeout=timeout,
                     headers={"User-Agent": USER_AGENT})
        return r.status_code == 200
    except Exception:
        return False


def search_mentions_hn(cve_id, *, session=None, timeout=20, limit=30) -> list:
    """Hacker News (Algolia) mentions. No key; ~30 req/min sustained.

    The alternative to search_mentions when Google blocks. Stories only:
    comments name CVEs in passing and pollute the count.
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
    chunks, seen_urls = [], set()
    for hit in hits:
        if "story" not in (hit.get("_tags") or []):
            continue
        titulo = (hit.get("title") or "").strip()
        url = (hit.get("url") or "").strip()
        if not titulo:
            continue
        if not url:
            url = f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
        if url in seen_urls:
            continue
        seen_urls.add(url)
        chunks.append({
            "cve_id": cve_id,
            "url": url,
            "title": titulo,
            "source": "Hacker News",
            "published": hit.get("created_at"),
        })
    return chunks


def load_attention(conn, limit=15, *, session=None) -> dict:
    """Searches press for the CVEs where attention matters (KEV/PoC/recent).

    Google first, HN as the fallback: in production Google has been blocked
    since day one, so HN is the source that actually brings data.
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
        conn.execute("""INSERT INTO attention_checks(cve_id,next_check_at)
            VALUES (?,CURRENT_TIMESTAMP+INTERVAL '24 hours')
            ON CONFLICT(cve_id) DO UPDATE SET checked_at=CURRENT_TIMESTAMP,
                next_check_at=excluded.next_check_at""", (cve_id,))
        total += sum(nuevas.values())
    return {"objetivos": len(objetivos), "nuevas": total,
            "google": con_google, "hn": con_hn}


def select_attention_targets(conn, limit=40) -> list:
    """CVEs where attention matters: with PoCs, in KEV or recent.

    `cves.published` is ISO TEXT ('2026-10-31T10:11:47.188Z'): it is compared as
    text against an ISO date, not cast to timestamp (which fails when empty).
    """
    rows = conn.execute("""
        SELECT e.cve_id AS cve_id, e.brand_name AS brand_name
        FROM enrichments e
        LEFT JOIN cves c ON c.cve_id = e.cve_id
        LEFT JOIN attention_checks ac ON ac.cve_id=e.cve_id
        WHERE (COALESCE(e.poc_count, 0) > 0 OR COALESCE(e.in_kev, 0) = 1
           OR c.published >= to_char(CURRENT_TIMESTAMP - INTERVAL '60 days', 'YYYY-MM-DD'))
          AND (ac.next_check_at IS NULL OR ac.next_check_at <= CURRENT_TIMESTAMP)
          AND c.record_state='PUBLISHED'
        ORDER BY ac.next_check_at ASC NULLS FIRST, COALESCE(e.in_kev, 0) DESC,
                 COALESCE(e.poc_count, 0) DESC, c.published DESC NULLS LAST, e.cve_id
        LIMIT ?
    """, (max(0, int(limit)),)).fetchall()
    return [(row["cve_id"], row["brand_name"]) for row in rows]


def upsert_media_mentions(conn, mentions) -> dict:
    """
    Inserts new mentions and adds to media_count only for the new ones.

    Returns {cve_id: new_mentions}. The (cve_id, url) PK is the lock: a URL
    already seen never counts again even if the feed republishes it.
    """
    nuevas: dict = {}
    for mention in mentions:
        cve_id = (mention.get("cve_id") or "").strip().upper()
        url = canonical_url(mention.get("url") or "")
        if not cve_id or not url:
            continue
        ensure_cve_stub(conn, cve_id)
        cursor = conn.execute("""
            INSERT INTO media_mentions (cve_id, url, title, source, published, kind, story_key, domain)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id, url) DO NOTHING
        """, (cve_id, url, mention.get("title"), mention.get("source"),
              mention.get("published"), mention.get('kind') or 'press',
              hashlib.sha256(re.sub(r'\W+', ' ', (mention.get('title') or url).lower()).strip().encode()).hexdigest(),
              urlsplit(url).netloc.lower()))
        if cursor.rowcount:  # 0 = URL already seen: not counted again
            nuevas[cve_id] = nuevas.get(cve_id, 0) + 1

    for cve_id, delta in nuevas.items():
        conn.execute("""
            INSERT INTO enrichments (cve_id, media_count) VALUES (?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                media_count = COALESCE(enrichments.media_count, 0) + excluded.media_count,
                updated_at = CURRENT_TIMESTAMP
        """, (cve_id, delta))
    return nuevas


def canonical_url(url):
    parts = urlsplit(str(url).strip())
    if parts.scheme.lower() not in ('https','http','urn'):
        return ''
    query = [(k,v) for k,v in parse_qsl(parts.query) if not k.lower().startswith('utm_') and k.lower() not in ('fbclid','gclid','ref')]
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip('/'), urlencode(sorted(query)), ''))


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
# Consecutive failed batches before the cycle stops calling the LLM.
RERANK_MAX_FAILURES = 2
RERANK_TITLE_CHARS = 160
RERANK_SUMMARY_CHARS = 180
# Cap per feed and per run: rerank is the expensive step (LLM), and the feeds
# republish dozens of old items that bring no new mentions.
RERANK_MAX_ENTRIES = 40
# Advisories with the CVE in the headline: they skip the model, but a catalog
# like MSRC's carries thousands of entries and only the recent stretch matters.
REGEX_MAX_ENTRIES = 250


def build_rerank_prompt(entries) -> str:
    lines = []
    for index, entry in enumerate(entries, 1):
        title = (entry.get("title") or "").replace('"', "'")[:RERANK_TITLE_CHARS]
        summary = (entry.get("summary") or "").replace('"', "'")[:RERANK_SUMMARY_CHARS]
        explicit_ids = ','.join(sorted(entry_cve_ids(entry))[:20])
        lines.append(f'{index}. title="{title}" summary="{summary}" explicit_cves="{explicit_ids}"')
    return RERANK_PROMPT.format(items="\n".join(lines))


def parse_rerank_reply(reply) -> list:
    """Pulls the JSON array out of the reply, tolerating fences or prose around it."""
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
    """Runs the entries through the LLM and returns {cve_id, brand_name, relevant}.

    Same order as `entries`. If the LLM fails on a batch, those entries stay
    unreranked (cve_id None) and the caller decides: the feed is not lost.
    """
    call = completer or (lambda prompt: llm_client.complete(
        prompt, system=RERANK_SYSTEM, config=config))
    out: list = [{} for _ in entries]
    failures = 0
    for start in range(0, len(entries), batch_size):
        chunk = entries[start:start + batch_size]
        try:
            reply = call(build_rerank_prompt(chunk))
        except Exception as exc:  # a dead LLM must not take the enrich down
            print(f"rerank: {type(exc).__name__}: {str(exc)[:120]}")
            # Two dead batches in a row mean the LLM is not going to answer this
            # cycle: burning 60 s per remaining batch only delays scoring.
            failures += 1
            if failures >= RERANK_MAX_FAILURES:
                print(f"rerank: giving up after {failures} failed batches")
                break
            continue
        failures = 0
        for item in parse_rerank_reply(reply):
            index = item.get("i")
            if not isinstance(index, int) or not 1 <= index <= len(chunk):
                continue
            cve_id = str(item.get("cve_id") or "").strip().upper() or None
            if cve_id and not CVE_PATTERN.fullmatch(cve_id):
                cve_id = None
            input_text = ' '.join(str(chunk[index-1].get(k) or '') for k in ('title','summary','url'))
            if cve_id and cve_id not in entry_cve_ids(chunk[index-1]):
                cve_id = None
            brand = str(item.get("brand_name") or "").strip() or None
            # A nickname with no CVE cannot be attached to any row.
            if brand and len(brand) > 48:
                brand = None
            if brand and brand.lower() not in input_text.lower():
                brand = None
            out[start + index - 1] = {
                "cve_id": cve_id,
                "brand_name": brand if cve_id else None,
                "relevant": item.get("relevant") is True,
            }
    return out


RERANK_URL_TTL_DAYS = 45
RERANK_EXTRACTOR_VERSION = 'rss-full-content-v2'


def _reranked_urls(conn, entries) -> set:
    """URLs that already went through rerank inside the retention window."""
    urls = [e.get("url") for e in entries if e.get("url")]
    if not urls:
        return set()
    try:
        rows = conn.execute(
            "SELECT url FROM reranked_urls WHERE url = ANY(?) "
            "AND extractor_version = ? "
            "AND reranked_at > CURRENT_TIMESTAMP - INTERVAL '%d days'"
            % RERANK_URL_TTL_DAYS,
            (urls, RERANK_EXTRACTOR_VERSION),
        ).fetchall()
    except Exception:
        return set()  # DB without the table (old schema): reprocess, do not break
    return {row["url"] for row in rows}


def _mark_reranked(conn, entries, reranked) -> None:
    """Records only the entries the LLM answered: failed batches get retried."""
    try:
        for entry, verdict in zip(entries, reranked):
            url = entry.get("url")
            if not url or not verdict:
                continue
            conn.execute(
                "INSERT INTO reranked_urls (url,extractor_version) VALUES (?,?) "
                "ON CONFLICT (url) DO UPDATE SET reranked_at=CURRENT_TIMESTAMP, extractor_version=excluded.extractor_version",
                (url,RERANK_EXTRACTOR_VERSION),
            )
    except Exception:
        pass


def mentions_from_rerank(entries, reranked) -> list:
    """Mentions built from the rerank; anything that is not about a vuln is dropped."""
    mentions = []
    for entry, verdict in zip(entries, reranked):
        if not verdict or verdict.get("relevant") is False:
            continue
        cve_id = verdict.get("cve_id")
        if not cve_id:
            continue
        url = entry.get("url") or ""
        explicit_ids = entry_cve_ids(entry)
        for linked_id in sorted(explicit_ids or {cve_id}):
            mentions.append({
            "cve_id": linked_id,
            "url": url or f"urn:cve:{cve_id}",
            "title": entry.get("title"),
            "source": entry.get("source"),
            # feedparser hands back RFC 822 ("Wed, 30 Sep 2026 07:00:00 GMT"):
            # storing it raw breaks every text comparison against an ISO date.
            "published": _iso_date(entry),
            "brand_name": verdict.get("brand_name") if linked_id == cve_id else None,
        })
    return mentions


def load_rss(conn, feeds, *, session=None, timeout=30, rerank=False,
             config=None, completer=None, regex_feeds=None) -> dict:
    """Downloads the feeds and accumulates mentions. A dead feed does not cut the rest.

    With `rerank` every entry goes through the LLM: it drops what is not a
    concrete vulnerability, resolves the CVE from the text and, when the
    headline uses a nickname (Log4Shell), stores it as the CVE's brand_name.

    `regex_feeds` are the ones that already carry the CVE in the headline
    (vendor and CERT advisories): there the regex is enough. They skip the LLM
    and the cap of 40, which in a catalog of thousands always lets the same 40
    in and never the new ones.
    """
    http = session or requests
    regex_set = set(regex_feeds or ())
    nuevas: dict = {}
    for url in dict.fromkeys([*(feeds or []), *(regex_feeds or [])]):
        try:
            response = http.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()
            content = getattr(response, "content", None) or response.text
        except Exception as exc:
            print(f"RSS {url}: {exc}")
            record_run(conn, 'feed:' + url, 'ERROR', {'error':type(exc).__name__})
            continue
        entries = parse_feed(content, source=_host(url))
        if rerank and url not in regex_set:
            # RSS rotates slowly: what was already reranked is not sent to the
            # LLM again (measured: ~5 min of model per cycle for 0 new mentions).
            known = _reranked_urls(conn, entries)
            fresh = [e for e in entries if (e.get("url") or "") not in known][:RERANK_MAX_ENTRIES]
            if fresh:
                reranked = rerank_entries(fresh, config=config, completer=completer)
                mentions = mentions_from_rerank(fresh, reranked)
                mentions.extend(collect_mentions([e for e,v in zip(fresh,reranked) if not v]))
                _mark_reranked(conn, fresh, reranked)
            else:
                mentions = []
        else:
            # Catalogs come newest first: the cap keeps the recent stretch and
            # the upsert takes care of the rest.
            mentions = collect_mentions(entries[:REGEX_MAX_ENTRIES])
        for mention in mentions:
            mention['kind'] = 'advisory' if url in regex_set or urlsplit(url).netloc.lower() == 'cvefeed.io' else 'press'
        for cve_id, delta in upsert_media_mentions(conn, mentions).items():
            nuevas[cve_id] = nuevas.get(cve_id, 0) + delta
        apply_mention_brands(conn, mentions)
        record_run(conn, 'feed:' + url, 'SUCCESS', {'entries':len(entries),'mentions':len(mentions),'kind':'advisory' if url in regex_set else 'press'})
    return nuevas


def apply_mention_brands(conn, mentions) -> int:
    """Writes into enrichments the nickname the headline uses for the CVE.

    The nickname is only accepted from the press: it is the only place it shows up.
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
            continue  # never overwrite an established nickname
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
    """Renders the sources.yaml template and appends `poc` when missing."""
    rendered = (template or DEFAULT_POC_QUERY).format(cve_id=cve_id).strip()
    return rendered if "poc" in rendered.lower() else f"{rendered} poc"


def _http_status(exc) -> int:
    """HTTP status of a requests exception, 0 when there was no response."""
    response = getattr(exc, "response", None)
    return int(getattr(response, "status_code", 0) or 0)


def fetch_poc_repos(cve_id, *, session=None, token=None, template=DEFAULT_POC_QUERY,
                    timeout=20, per_page=30) -> tuple:
    """(GitHub total, repos with metrics, HTTP status).

    The status matters: a 403/429 is a rate limit, not "this CVE has no PoCs".
    """
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
        if data.get("incomplete_results"):
            return 0, [], 206
    except Exception as exc:
        print(f"GitHub {cve_id}: {exc}")
        return 0, [], _http_status(exc)

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
    return total, repos, 200


def upsert_pocs(conn, cve_id, repos) -> int:
    """Stores the repos with their metrics: they refresh on every pass."""
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
    Counts repos that are probably PoCs. Without GITHUB_TOKEN the API may
    return 403 on rate limit: it gets logged and the run continues with 0.
    """
    total, _, _ = fetch_poc_repos(
        cve_id, session=session, token=token, template=template, timeout=timeout,
        per_page=1,
    )
    return total


def upsert_poc_count(conn, cve_id, count) -> None:
    """Replaces poc_count: the search is the truth, nothing is added blindly."""
    cve_id = (cve_id or "").strip().upper()
    if not cve_id:
        return
    ensure_cve_stub(conn, cve_id)
    source_poc_count(conn, cve_id, max(0,int(count or 0)), 'github')


def select_poc_targets(conn, limit=25) -> list:
    """Bounded queue of due checks, including previous positive and empty results."""
    rows = conn.execute("""
        SELECT e.cve_id AS cve_id
        FROM enrichments e
        LEFT JOIN cves c ON c.cve_id = e.cve_id
        LEFT JOIN poc_checks pc ON pc.cve_id = e.cve_id
        WHERE (pc.next_check_at IS NULL OR pc.next_check_at <= CURRENT_TIMESTAMP)
          AND (e.media_count > 0 OR c.raw_json IS NOT NULL OR c.published IS NOT NULL
               OR c.description IS NOT NULL OR c.cvss_score IS NOT NULL)
        ORDER BY pc.next_check_at ASC NULLS FIRST,
                 (e.media_count > 0) DESC, e.media_count DESC,
                 c.published DESC NULLS LAST, e.cve_id
        LIMIT ?
    """, (max(0, int(limit)),)).fetchall()
    return [row["cve_id"] for row in rows]


# The GitHub search allows 30 requests per minute with a token (10 without) and
# answers 403 past that. With no pause, a big batch burns the quota, fails
# silently and even overwrites the good count with poc_count=0.
GITHUB_MIN_INTERVAL = 2.1
GITHUB_RATE_LIMIT_WAIT = 60
RATE_LIMIT_STATUS = (403, 429)


def record_poc_check(conn, cve_id, *, successful) -> None:
    """Refresh successes after a day; retry failures after fifteen minutes."""
    ensure_cve_stub(conn, cve_id)
    conn.execute("""
        INSERT INTO poc_checks (cve_id, next_check_at, successful)
        VALUES (?, CURRENT_TIMESTAMP + (? * INTERVAL '1 second'), ?)
        ON CONFLICT (cve_id) DO UPDATE SET
            checked_at = CURRENT_TIMESTAMP,
            next_check_at = excluded.next_check_at,
            successful = excluded.successful
    """, (cve_id, 86400 if successful else 900, successful))


def load_pocs(conn, cve_ids, *, session=None, token=None,
              template=DEFAULT_POC_QUERY, pause=None, sleep=None) -> int:
    wait_s = GITHUB_MIN_INTERVAL if pause is None else pause
    dormir = sleep or time.sleep
    count = 0
    for i, cve_id in enumerate(cve_ids or []):
        if i and wait_s:
            dormir(wait_s)
        total, repos, status = fetch_poc_repos(
            cve_id, session=session, token=token, template=template,
        )
        if status in RATE_LIMIT_STATUS:
            # A 403 here says nothing about the CVE: wait out the window and retry.
            dormir(GITHUB_RATE_LIMIT_WAIT)
            total, repos, status = fetch_poc_repos(
                cve_id, session=session, token=token, template=template,
            )
        if status != 200:
            record_poc_check(conn, cve_id, successful=False)
            continue  # failures say nothing about the existing exploitation evidence
        upsert_poc_count(conn, cve_id, total)
        if total == 0:
            conn.execute("DELETE FROM pocs WHERE cve_id = ?", (cve_id,))
        upsert_pocs(conn, cve_id, repos)
        record_poc_check(conn, cve_id, successful=True)
        count += 1
    return count


# --------------------------------------------------------------------------
# Branding + tone_score (LLM with heuristic fallback)
# --------------------------------------------------------------------------
TONE_SYSTEM = (
    "You are a security-news hype analyst. You answer with JSON only, no prose."
)

TONE_MIN, TONE_MAX = 0.0, 10.0

# Heuristic fallback cues (the LLM is the main path).
PANIC_CUES = (
    "apocalyp", "catastroph", "chaos", "devastat", "nightmare", "massive",
    "critical", "severe", "under attack", "wormable", "zero-day", "0day",
    "exploited in the wild", "emergency",
)
CALM_CUES = (
    "advisory", "patch", "mitigat", "coordinated disclosure", "routine",
    "low severity",
)
# Known exploit names: the heuristic cannot guess them all.
KNOWN_BRANDS = (
    "Log4Shell", "Spring4Shell", "Heartbleed", "Shellshock", "RegreSSHion",
    "Dirty Pipe", "Dirty COW", "BlueKeep", "EternalBlue",
)
BRAND_CUES = ("named", "dubbed", "christened", "nicknamed", "called")
# Token with inner uppercase: Log4Shell, Pwn2Own (CVE or HTTP are left out).
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
    """0 = dry/technical, 10 = panic. Exclamation marks + wording."""
    text = (title or "").lower()
    score = 3.0
    panic = sum(1 for cue in PANIC_CUES if cue in text)
    calm = sum(1 for cue in CALM_CUES if cue in text)
    score += min(6.0, 2.0 * panic)
    score += min(3.0, float(text.count("!")))
    score -= min(4.0, 2.0 * calm)
    return round(max(TONE_MIN, min(TONE_MAX, score)), 1)


def heuristic_branding(text) -> tuple:
    """(branding, brand_name) from a known name, CamelCase or 'dubbed X'."""
    raw = text or ""

    named = NAMED_BRAND.search(raw)
    if named:
        return True, named.group(1)
    if re.search(r'compared to|similar to|worse than|like log4shell|next log4shell', raw, re.I):
        return False, None

    lowered = raw.lower()
    for brand in KNOWN_BRANDS:
        if brand.lower() in lowered:
            return True, brand

    named = NAMED_BRAND.search(raw)
    if named:
        return True, named.group(1)

    return False, None


def analyze_tone_batch(items, *, completer=None, config=None, session=None) -> list:
    """
    One LLM call per batch. If the model fails or returns broken JSON, every
    item falls back to the heuristic (a row never ends up without tone_score).
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
            # No model reply (or no usable tone_score) means the heuristic decides.
            branding, brand_name = heuristic_branding(title)
            results.append({
                "cve_id": cve_id,
                "tone_score": heuristic_tone(title),
                "branding": branding,
                "brand_name": brand_name,
                "source": "heuristic", "model": "heuristic-v2", "sample": title,
            })
            continue
        branding = _as_bool(entry.get("branding"))
        brand_name = _as_text(entry.get('brand_name'))
        if not brand_name or brand_name.lower() not in title.lower() or brand_name.lower() in {'openssl','sharepoint','microsoft','windows','linux','chrome','firefox','pwn2own'}:
            branding = False
        results.append({
            "cve_id": cve_id,
            "tone_score": tone,
            "branding": branding,
            "brand_name": brand_name if branding else None,
            "source": "llm",
            "model": getattr(config, 'model', None) or os.getenv('LLM_MODEL') or 'configured-default',
            "sample": title,
        })
    return results


def upsert_tone(conn, results) -> int:
    """Writes ONLY tone_score/branding/brand_name: KEV and EPSS stay untouched."""
    count = 0
    for result in results or []:
        cve_id = (result.get("cve_id") or "").strip().upper()
        tone = _to_tone(result.get("tone_score"))
        if not cve_id or tone is None:
            continue  # no usable tone means no write: it smells like an invented value
        ensure_cve_stub(conn, cve_id)
        conn.execute("""
            INSERT INTO enrichments (cve_id, tone_score, branding, brand_name, tone_method, tone_model)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                tone_score = excluded.tone_score,
                branding = CASE WHEN excluded.branding=1 THEN 1 ELSE enrichments.branding END,
                brand_name = COALESCE(excluded.brand_name, enrichments.brand_name),
                tone_method = excluded.tone_method,
                tone_model = excluded.tone_model,
                updated_at = CURRENT_TIMESTAMP
        """, (
            cve_id,
            tone,
            1 if result.get("branding") else 0,
            _as_text(result.get("brand_name")),
            result.get('source') or 'unspecified', result.get('model') or 'heuristic-v2',
        ))
        observe(conn, cve_id, 'tone', 'analysis', hashlib.sha256(json.dumps(result,sort_keys=True,default=str).encode()).hexdigest(), payload=result)
        count += 1
    return count


def select_tone_targets(conn, limit=50) -> list:
    """Headlines to analyze: the CVEs that never had a tone_score come first."""
    rows = conn.execute("""
        SELECT m.cve_id AS cve_id, string_agg(m.title, E'\\n' ORDER BY m.id DESC) AS title
        FROM (
            SELECT *, row_number() OVER (PARTITION BY cve_id ORDER BY published DESC NULLS LAST, id DESC) AS rank
            FROM media_mentions WHERE kind='press' AND title IS NOT NULL AND title <> ''
        ) m
        LEFT JOIN enrichments e ON e.cve_id=m.cve_id
        WHERE m.rank <= 5
        GROUP BY m.cve_id
        ORDER BY bool_and(e.tone_score IS NOT NULL), max(m.id) DESC
        LIMIT ?
    """, (max(0,int(limit)),)).fetchall()
    return [{'cve_id':row['cve_id'],'title':row['title']} for row in rows]

def load_tone(conn, *, limit=50, batch_size=10, completer=None, config=None,
              session=None) -> int:
    """One batch = one call. 10 headlines per batch by default."""
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
# Config, orchestration and CLI
# --------------------------------------------------------------------------
def load_sources_config(path=None) -> dict:
    """The `sources:` block of config/sources.yaml ({} when it does not exist)."""
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
    """Runs the six signals in order and returns a summary of counts."""
    sources = load_sources_config(sources_path)
    path = init_db(db_path)  # idempotent: creates media_mentions when missing
    conn = get_db(path)
    summary = {"kev": 0, "epss": 0, "rss": {}, "poc": 0, "tone": 0, "attention": {}}
    skip_llm = skip_llm or os.getenv('LLM_PROVIDER', '').lower() == 'none'
    errors = []
    def step(name, fn):
        result = run_source(conn, name, fn)
        if isinstance(result, dict) and result.get('error'):
            errors.append(name)
        return result
    try:
        if not skip_kev:
            summary['kev'] = step('kev', lambda: load_kev(conn))
        if not skip_epss:
            summary['epss'] = step('epss', lambda: load_epss(conn))
        if not skip_rss:
            summary['rss'] = step('rss', lambda: load_rss(
                conn, sources.get('rss') or [], session=session,
                rerank=not skip_llm and bool(sources.get('rerank_feeds')),
                completer=completer, regex_feeds=sources.get('rss_regex_only') or []))
        github_cfg = sources.get('github_search') or {}
        if not skip_github and github_cfg.get('enabled'):
            summary['poc'] = step('github', lambda: load_pocs(
                conn, select_poc_targets(conn, github_limit), session=session,
                template=github_cfg.get('query_template') or DEFAULT_POC_QUERY))
        if not skip_llm:
            summary['tone'] = step('tone', lambda: load_tone(
                conn, limit=llm_limit, batch_size=llm_batch_size, completer=completer))
        attention_cfg = sources.get('attention') or {}
        if not skip_attention and attention_cfg.get('enabled', True):
            summary['attention'] = step('attention', lambda: load_attention(
                conn, int(attention_cfg.get('limit', 15)), session=session))
        summary['errors'] = errors
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
    parser.add_argument("--skip-rss", action="store_true", help="Does not read the RSS feeds.")
    parser.add_argument("--skip-github", action="store_true", help="No busca PoCs en GitHub.")
    parser.add_argument("--skip-llm", action="store_true", help="No llama al LLM (no escribe tone/branding).")
    parser.add_argument("--skip-attention", action="store_true",
                        help="Does not search press coverage for CVEs with KEV/PoC/recency (Google + HN).")
    parser.add_argument("--rss-only", action="store_true", help="RSS only (local): implies every other --skip-*.")
    parser.add_argument("--github-limit", type=int, default=25, help="CVEs a buscar en GitHub (default 25).")
    parser.add_argument("--llm-limit", type=int, default=50, help="CVEs to analyze with the LLM (default 50).")
    parser.add_argument("--llm-batch-size", type=int, default=10, help="Headlines per call (default 10).")
    parser.add_argument("--sources", default=None, help="Ruta a sources.yaml (default config/sources.yaml).")
    parser.add_argument("--db-path", default=None, help="Test schema. Production: DATABASE_URL.")
    parser.add_argument("--llm-smoke", action="store_true", help="One real LLM call, then exits.")
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
    """Live smoke: a single real call. Never prints the API key."""
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
    """Accepts an object or an array, with or without ```json ... ``` around it."""
    raw = (text or "").strip()
    if not raw:
        raise ValueError("empty LLM response")

    fenced = re.search(r"```(?:json)?\s*(.+?)```", raw, re.DOTALL)
    if fenced:
        raw = fenced.group(1).strip()

    starts = [index for index in (raw.find("["), raw.find("{")) if index >= 0]
    if not starts:
        raise ValueError("LLM response without JSON")
    payload, _ = json.JSONDecoder().raw_decode(raw[min(starts):])

    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    raise ValueError("LLM response with unexpected JSON")


def _looks_like_brand(token: str) -> bool:
    """FooShell yes; CVE, HTTP or 2026 no."""
    if len(token) < 5:
        return False
    if any(char.isdigit() for char in token) and any(char.isalpha() for char in token):
        return True
    return any(char.islower() for char in token) and any(char.isupper() for char in token[1:])


def _strip_html(value) -> str:
    text = re.sub(r'<(script|style)\b[^>]*>.*?</\1\s*>', ' ', str(value or ''), flags=re.I|re.S)
    text = re.sub(r'<!--.*?-->', ' ', text, flags=re.S)
    return ' '.join(unescape(re.sub(r'<[^>]+>', ' ', text)).split())


def _iso_date(entry) -> str | None:
    """Feed date as ISO 8601 UTC; when it cannot be parsed, the raw text."""
    stamp = entry.get("published_parsed") or entry.get("updated_parsed")
    if not stamp:
        return entry.get("published") or entry.get("updated")
    return datetime(*stamp[:6], tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _host(url: str) -> str:
    match = re.match(r"https?://([^/]+)", url or "")
    return match.group(1) if match else ""


def _to_float(value):
    try:
        number = float(value)
        return number if math.isfinite(number) else None
    except (TypeError, ValueError):
        return None


def _to_tone(value):
    """tone_score clamped to 0-10, or None when the value is not numeric."""
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
