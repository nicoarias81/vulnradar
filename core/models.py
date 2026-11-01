"""
Modelos de dominio alineados a schema.sql — dataclasses planas, sin ORM.
"""
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class CveRecord:
    """Fila de la tabla cves."""

    cve_id: str
    published: Optional[str] = None
    last_modified: Optional[str] = None
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_severity: Optional[str] = None
    raw_json: Optional[str] = None
    synced_at: Optional[str] = None


@dataclass
class Enrichment:
    """Fila de la tabla enrichments."""

    cve_id: str
    in_kev: bool = False
    kev_date: Optional[str] = None
    ransomware_use: bool = False
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    poc_count: int = 0
    media_count: int = 0
    tone_score: Optional[float] = None
    branding: bool = False
    brand_name: Optional[str] = None
    wild_confirmation: bool = False
    updated_at: Optional[str] = None


@dataclass
class Score:
    """Fila de la tabla scores: una vigente por CVE (UNIQUE(cve_id))."""

    cve_id: str
    hype: float
    reality: float
    category: str
    calculated_at: Optional[str] = None


@dataclass
class NormalizedCve:
    """Esquema interno normalizado (ver ARCHITECTURE.md) que consume el scoring."""

    cve_id: str
    published: Optional[str] = None
    cvss: float = 0.0
    cvss_vector: Optional[str] = None
    signals: dict[str, Any] = field(default_factory=dict)
