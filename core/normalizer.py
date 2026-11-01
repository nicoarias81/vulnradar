"""
Normalización — CVE List V5 al esquema de la tabla cves y señales internas.

`build_signals` es la ÚNICA fuente de verdad del mapeo DB -> fórmulas v2:
lo usan el scoring agent (fila unida) y los tests.
"""
import json
import re
from typing import Any, Mapping, Optional

from core.models import CveRecord, Enrichment, NormalizedCve
from core.scoring import exploit_ease

# Orden de preferencia de CVSS: v3.1, luego v3.0, luego v4.0.
CVSS_KEYS = ("cvssV3_1", "cvssV3_0", "cvssV4_0")

# Escalas de las señales blandas (antes inline en scoring_agent).
MEDIA_COUNT_PER_POINT = 2.0   # media_score = min(media_count / 2, 10)
POC_COUNT_PER_POINT = 2.0     # poc_score   = min(poc_count * 2, 10)
SCALE_CAP = 10.0


# Los CNA escriben el producto con la versión adentro: "Google Chrome prior to
# 55.0.2883.75 for Mac, Windows and Linux". Como filtro de producto eso es ruido:
# cada versión sería una opción distinta del desplegable.
VERSION_SPLIT = re.compile(
    r"\s+(?:prior\s+to|before|through|up\s+to|all\s+versions)\s+",
    re.IGNORECASE,
)
# "versions" por sí solo aparece en frases ("customize the mobile version
# without redirections"): sólo corta si le sigue un número o un comparador.
VERSION_WORD = re.compile(r"\s+versions?\s+(?=[<>=~]?\s*[vV]?\d)", re.IGNORECASE)
VERSION_TAIL = re.compile(r"\s*[<>=~]+\s*[\w.]+.*$")
VERSION_NUMBER = re.compile(r"\s+v?\d+(?:\.\d+)+.*$")
PRODUCT_EMPTY = {"", "*", "-", "n/a", "unknown"}


def clean_product(product: str) -> str:
    """Producto sin la versión pegada: 'Chrome prior to 120' -> 'Chrome'."""
    text = (product or "").strip()
    text = VERSION_SPLIT.split(text, maxsplit=1)[0]
    text = VERSION_WORD.split(text, maxsplit=1)[0]
    text = VERSION_TAIL.sub("", text)
    text = VERSION_NUMBER.sub("", text)
    return text.strip(" ,;:-") or (product or "").strip()


def extract_vendor_product(data: Mapping[str, Any]) -> tuple:
    """(vendor, product) del primer `affected` que declare producto.

    El registro CVE 5.0 lo pone en `containers.cna.affected[]` y, si el CNA no lo
    declaró, en los bloques ADP.
    """
    if not isinstance(data, Mapping):
        return None, None
    containers = data.get("containers") or {}
    blocks = [containers.get("cna") or {}]
    blocks.extend(containers.get("adp") or [])
    for block in blocks:
        for item in (block or {}).get("affected") or []:
            product = clean_product(str(item.get("product") or ""))
            if product.lower() in PRODUCT_EMPTY:
                continue
            vendor = str(item.get("vendor") or "").strip() or None
            if vendor and vendor.lower() in PRODUCT_EMPTY:
                vendor = None
            return vendor, product
    return None, None


def normalize_cve_list_v5(raw: Mapping[str, Any]) -> Optional[dict]:
    """
    Convierte un JSON CVE List V5 (dataType CVE_RECORD) en los campos de cves.
    Devuelve None si el registro no trae cveId.
    """
    meta = raw.get("cveMetadata") or {}
    cve_id = (meta.get("cveId") or "").strip()
    if not cve_id:
        return None

    containers = raw.get("containers") or {}
    cna = containers.get("cna") or {}
    metric = _extract_cvss(cna, containers.get("adp") or [])

    return {
        "cve_id": cve_id,
        "published": meta.get("datePublished"),
        "last_modified": meta.get("dateUpdated") or meta.get("dateModified"),
        "description": _extract_description(cna),
        "cvss_score": _as_float(metric.get("baseScore")),
        "cvss_vector": metric.get("vectorString"),
        "cvss_severity": metric.get("baseSeverity"),
        "raw_json": json.dumps(raw, ensure_ascii=False),
    }


def build_normalized_cve(cve_row, enrichment_row=None) -> NormalizedCve:
    """Arma el esquema interno normalizado a partir de una fila de DB."""
    cve = CveRecord(
        cve_id=_get(cve_row, "cve_id") or "",
        published=_get(cve_row, "published"),
        cvss_score=_as_float(_get(cve_row, "cvss_score")),
    )
    enr = Enrichment(
        cve_id=cve.cve_id,
        in_kev=bool(_get(enrichment_row, "in_kev")),
        ransomware_use=bool(_get(enrichment_row, "ransomware_use")),
        wild_confirmation=bool(_get(enrichment_row, "wild_confirmation")),
        epss=_as_float(_get(enrichment_row, "epss")),
        poc_count=_as_int(_get(enrichment_row, "poc_count")),
        media_count=_as_int(_get(enrichment_row, "media_count")),
        tone_score=_as_float(_get(enrichment_row, "tone_score")),
        branding=bool(_get(enrichment_row, "branding")),
    )

    return NormalizedCve(
        cve_id=cve.cve_id,
        published=cve.published,
        cvss=cve.cvss_score or 0.0,
        cvss_vector=_get(cve_row, "cvss_vector"),
        signals={
            "in_kev": enr.in_kev,
            "epss": enr.epss or 0.0,
            "media_count": enr.media_count,
            "poc_count": enr.poc_count,
            "tone_score": enr.tone_score or 0.0,
            "branding": enr.branding,
            "wild_confirmation": enr.wild_confirmation,
            "ransomware_use": enr.ransomware_use,
        },
    )


def build_signals(cve_row, enrichment_row=None) -> dict:
    """Señales planas compatibles con core.scoring.score_cve."""
    normalized = build_normalized_cve(cve_row, enrichment_row)
    signals = normalized.signals

    return {
        "cvss": normalized.cvss,
        "in_kev": signals["in_kev"],
        "epss": signals["epss"],
        "wild_confirmation": signals["wild_confirmation"],
        "ransomware_use": signals["ransomware_use"],
        "media_score": media_score(signals["media_count"]),
        "poc_score": poc_score(signals["poc_count"]),
        "exploit_ease": exploit_ease(normalized.cvss_vector),
        "tone_score": signals["tone_score"],
        "branding": signals["branding"],
    }


def media_score(media_count: int) -> float:
    return min(media_count / MEDIA_COUNT_PER_POINT, SCALE_CAP)


def poc_score(poc_count: int) -> float:
    return min(poc_count * POC_COUNT_PER_POINT, SCALE_CAP)


def _extract_cvss(cna: Mapping[str, Any], adp: list) -> dict:
    """Primer bloque CVSS según CVSS_KEYS, buscando en cna y luego en adp."""
    blocks = [m for m in (cna.get("metrics") or []) if isinstance(m, Mapping)]
    for container in adp:
        if isinstance(container, Mapping):
            blocks.extend(m for m in (container.get("metrics") or []) if isinstance(m, Mapping))

    for key in CVSS_KEYS:
        for block in blocks:
            candidate = block.get(key)
            if isinstance(candidate, Mapping):
                return candidate
    return {}


def _extract_description(cna: Mapping[str, Any]) -> str:
    descriptions = [d for d in (cna.get("descriptions") or []) if isinstance(d, Mapping)]
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value") or ""
    return descriptions[0].get("value", "") if descriptions else ""


def _get(row, key: str):
    """Lee una clave de un dict o de una fila (Row / mapping)."""
    if row is None:
        return None
    if isinstance(row, Mapping):
        return row.get(key)
    try:
        return row[key]
    except (IndexError, KeyError):
        return None


def _as_float(value) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value) -> int:
    number = _as_float(value)
    return int(number) if number is not None else 0
