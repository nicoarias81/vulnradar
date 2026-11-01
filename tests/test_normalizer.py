"""CVE List V5 normalization tests and mapping to scoring signals."""
import copy
import json
from pathlib import Path

import pytest

from core.normalizer import build_signals, media_score, normalize_cve_list_v5, poc_score

FIXTURES = Path(__file__).parent / "fixtures" / "cvelistV5"


@pytest.fixture
def cve_v5_raw() -> dict:
    return json.loads((FIXTURES / "CVE-2026-0001.json").read_text(encoding="utf-8"))


def test_normalizes_cves_table_fields(cve_v5_raw):
    record = normalize_cve_list_v5(cve_v5_raw)

    assert record["cve_id"] == "CVE-2026-0001"
    assert record["published"] == "2026-01-06T12:30:00.000Z"
    assert record["last_modified"] == "2026-01-09T08:15:00.000Z"  # dateUpdated
    assert record["description"].startswith("HumoRadar Gateway 1.0 allows")
    assert record["cvss_score"] == pytest.approx(9.8)
    assert record["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert record["cvss_severity"] == "CRITICAL"

    raw_json = json.loads(record["raw_json"])
    assert raw_json == cve_v5_raw


def test_last_modified_falls_back_to_dateModified_without_dateUpdated(cve_v5_raw):
    raw = copy.deepcopy(cve_v5_raw)
    del raw["cveMetadata"]["dateUpdated"]

    record = normalize_cve_list_v5(raw)

    assert record["last_modified"] == "2026-01-08T00:00:00.000Z"


def test_prefers_cvss_v31_over_v30_and_v40():
    raw = {
        "cveMetadata": {"cveId": "CVE-2026-0002"},
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "Order test"}],
                "metrics": [
                    {"cvssV4_0": {"baseScore": 4.0, "vectorString": "CVSS:4.0/AV:N", "baseSeverity": "MEDIUM"}},
                    {"cvssV3_0": {"baseScore": 3.0, "vectorString": "CVSS:3.0/AV:N", "baseSeverity": "LOW"}},
                    {"cvssV3_1": {"baseScore": 8.1, "vectorString": "CVSS:3.1/AV:N", "baseSeverity": "HIGH"}},
                ],
            }
        },
    }

    assert normalize_cve_list_v5(raw)["cvss_score"] == pytest.approx(8.1)


@pytest.mark.parametrize(
    "metric,key,expected_score",
    [
        ({"cvssV3_0": {"baseScore": 6.5, "vectorString": "CVSS:3.0/AV:N", "baseSeverity": "MEDIUM"}}, "cvssV3_0", 6.5),
        ({"cvssV4_0": {"baseScore": 7.3, "vectorString": "CVSS:4.0/AV:N", "baseSeverity": "HIGH"}}, "cvssV4_0", 7.3),
    ],
)
def test_fallback_cvss(metric, key, expected_score):
    raw = {
        "cveMetadata": {"cveId": "CVE-2026-0003"},
        "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Fallback"}], "metrics": [metric]}},
    }

    record = normalize_cve_list_v5(raw)

    assert record["cvss_score"] == pytest.approx(expected_score)


def test_cvss_from_adp_when_cna_has_no_metrics():
    raw = {
        "cveMetadata": {"cveId": "CVE-2026-0004"},
        "containers": {
            "cna": {"descriptions": [{"lang": "en", "value": "No metrics"}]},
            "adp": [
                {
                    "providerMetadata": {"orgId": "adp-example"},
                    "metrics": [{"cvssV3_1": {"baseScore": 5.5, "vectorString": "CVSS:3.1/AV:L", "baseSeverity": "MEDIUM"}}],
                }
            ],
        },
    }

    assert normalize_cve_list_v5(raw)["cvss_score"] == pytest.approx(5.5)


def test_record_without_cve_id_is_dropped():
    assert normalize_cve_list_v5({"containers": {"cna": {}}}) is None


def test_minimal_record_without_metrics_or_description():
    record = normalize_cve_list_v5({"cveMetadata": {"cveId": "CVE-2026-0005"}})

    assert record["cve_id"] == "CVE-2026-0005"
    assert record["description"] == ""
    assert record["cvss_score"] is None
    assert record["cvss_vector"] is None


@pytest.mark.parametrize(
    "media_count,poc_count,expected_media,expected_poc",
    [
        (0, 0, 0.0, 0.0),
        (1, 1, 0.5, 2.0),
        (12, 5, 6.0, 10.0),
        (40, 40, 10.0, 10.0),  # both capped
    ],
)
def test_media_and_poc_scales(media_count, poc_count, expected_media, expected_poc):
    assert media_score(media_count) == pytest.approx(expected_media)
    assert poc_score(poc_count) == pytest.approx(expected_poc)


def test_build_signals_maps_db_rows_to_formulas():
    cve_row = {
        "cve_id": "CVE-2026-0006",
        "published": "2026-01-06",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
    enrichment_row = {
        "in_kev": 1,
        "epss": 0.87,
        "wild_confirmation": 1,
        "ransomware_use": 0,
        "media_count": 12,
        "poc_count": 5,
        "tone_score": 8.0,
        "branding": 1,
    }

    signals = build_signals(cve_row, enrichment_row)

    assert signals == {
        "cvss": 9.8,
        "in_kev": True,
        "epss": 0.87,
        "wild_confirmation": True,
        "ransomware_use": False,
        "media_score": 6.0,   # min(12/2, 10)
        "poc_score": 10.0,    # min(5*2, 10)
        "exploit_ease": 10.0,  # AV:N/AC:L/PR:N/UI:N
        "tone_score": 8.0,
        "branding": True,
    }


def test_build_signals_without_enrichment_uses_zeros():
    signals = build_signals({"cve_id": "CVE-2026-0007", "cvss_score": None}, None)

    assert signals["cvss"] == 0.0
    assert signals["in_kev"] is False
    assert signals["epss"] == 0.0
    assert signals["media_score"] == 0.0
    assert signals["poc_score"] == 0.0
