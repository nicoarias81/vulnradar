"""Offline semantic audit, independent of the regression suite.

No network, persistent DB, alerts or score writes. Exit 1 means one or more
proposed safety/quality requirements are violated, not that pytest failed.
See docs/SCORING_REVIEW.md for scope and interpretation.
"""
from __future__ import annotations

import json
import itertools
import hashlib
import math
import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents import enrichment_agent as enrichment
from agents.intel_agent import sync_exploitdb
from agents.scoring_agent import SCORING_VERSION
from core.normalizer import build_signals, normalize_cve_list_v5
from core.scoring import calculate_reality, exploit_ease, score_cve


class EmptyConnection:
    def execute(self, *args, **kwargs):
        return self

    def rollback(self):
        pass
    def commit(self):
        pass

    def close(self):
        pass


class EmptyHTTP:
    def __init__(self):
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        return self

    content = b'<rss version="2.0"><channel><title>Fixture</title></channel></rss>'

    def raise_for_status(self):
        pass


def audit() -> dict:
    checks = []

    def check(name, kind, passed, evidence):
        checks.append({"name": name, "kind": kind, "passed": bool(passed), "evidence": evidence})

    # These properties test arithmetic, not empirical prediction quality.
    ranges = {
        "in_kev": (False, True), "wild_confirmation": (False, True),
        "ransomware_use": (False, True), "branding": (False, True),
        "epss": (0, 0.001, 0.1, 0.7, 1), "poc_score": (0, 1, 5, 10),
        "cvss": (0, 5, 10), "media_score": (0, 1, 10),
        "tone_score": (0, 5, 10), "exploit_ease": (0, 4, 10),
    }
    checked = 0
    violations = 0
    for values in itertools.product(*ranges.values()):
        scores = score_cve(dict(zip(ranges, values)))
        checked += 1
        violations += any(not math.isfinite(scores[k]) or not 0 <= scores[k] <= 10 for k in ("hype", "reality"))
    check("normalized_grid_is_finite_and_bounded", "arithmetic", violations == 0,
          {"combinations": checked, "violations": violations})
    monotone = True
    for key, values in ranges.items():
        previous = {"hype": -1, "reality": -1}
        for value in values:
            current = score_cve({key: value})
            monotone &= all(current[k] >= previous[k] for k in previous)
            previous = {k: current[k] for k in ('hype','reality')}
    check("individual_signals_are_numerically_monotone", "arithmetic", monotone,
          {"signals": len(ranges), "scope": "Each signal varied independently; category semantics evaluated separately."})

    example = score_cve({
        "in_kev": True, "epss": 0.01, "exploit_ease": 10, "cvss": 9.8,
        "media_score": 10, "tone_score": 9, "branding": True,
    })
    check("known_exploitation_not_overhyped", "model_safety", example["category"] != "Overhyped", example)

    maximum = calculate_reality({
        "in_kev": False, "epss": 1, "poc_score": 10,
        "wild_confirmation": True, "exploit_ease": 10,
    })
    check("confirmed_non_kev_can_reach_high_reality", "model_safety", maximum >= 6, {"maximum_without_ransomware": maximum})

    invalid = score_cve({"epss": -1, "cvss": -10, "tone_score": -5,
                         "media_score": -5, "poc_score": -5, "exploit_ease": -10})
    infinite = calculate_reality({"exploit_ease": math.inf})
    check("finite_bounded_scores", "input_integrity",
          all(math.isfinite(invalid[k]) and 0 <= invalid[k] <= 10 for k in ("hype", "reality"))
          and math.isfinite(infinite), {"negative_inputs": invalid, "infinite_ease_result": repr(infinite)})

    check("invalid_vector_not_maximum_ease", "input_integrity", exploit_ease("garbage") != 10,
          {"ease_for_garbage": exploit_ease("garbage")})
    base = "CVSS:4.0/AV:N/AC:L/AT:{at}/PR:N/UI:{ui}/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    easy = exploit_ease(base.format(at="N", ui="N"))
    constrained = exploit_ease(base.format(at="P", ui="A"))
    check("cvss4_constraints_affect_ease", "input_integrity", constrained < easy,
          {"AT_N_UI_N": easy, "AT_P_UI_A": constrained})

    raw = {"cveMetadata": {"cveId": "CVE-2026-1234", "state": "REJECTED"}}
    check("rejected_record_not_treated_as_normal_cve", "input_integrity",
          normalize_cve_list_v5(raw) is None, {"normalizer_accepts_rejected": normalize_cve_list_v5(raw) is not None})
    missing = build_signals({"cve_id": "CVE-2026-1234"}, None)
    known_zero = build_signals({"cve_id": "CVE-2026-1234", "cvss_score": 0}, {
        "epss": 0, "poc_count": 0, "media_count": 0, "tone_score": 0,
        "in_kev": 0, "branding": 0, "wild_confirmation": 0, "ransomware_use": 0,
    })
    check("missing_evidence_distinguished_from_zero", "model_safety", missing != known_zero,
          {"same_signals": missing == known_zero})

    brand = enrichment.heuristic_branding("OpenSSL security advisory")
    check("product_name_not_vulnerability_brand", "input_integrity", not brand[0], {"branding": brand})
    reply = '[{"i":1,"cve_id":"CVE-2026-99999","brand_name":"InventedShell","relevant":true}]'
    verdict = enrichment.rerank_entries([{"title": "CVE-2026-1234 advisory", "summary": ""}], completer=lambda _: reply)
    check("llm_identifier_grounded_in_input", "input_integrity",
          verdict[0].get("cve_id") != "CVE-2026-99999", {"verdict": verdict})

    # Execute the real write SQL in a transient SQLite DB: neither operation
    # below uses Postgres-only syntax, and no persistent data is touched.
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE TABLE cves (cve_id TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE enrichments (cve_id TEXT PRIMARY KEY, poc_count INTEGER, github_poc_count INTEGER DEFAULT 0, exploitdb_poc_count INTEGER DEFAULT 0, updated_at TEXT)")
        conn.execute("CREATE TABLE evidence (cve_id TEXT,source TEXT,kind TEXT,external_id TEXT,url TEXT,event_date TEXT,trusted BOOLEAN,payload TEXT,active BOOLEAN DEFAULT true,observed_at TEXT DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(cve_id,source,kind,external_id))")
        csv = "id,codes\n1,CVE-2026-1234\n2,CVE-2026-1234\n"
        sync_exploitdb(conn, csv_text=csv)
        before = conn.execute("SELECT poc_count FROM enrichments").fetchone()[0]
        enrichment.upsert_poc_count(conn, "CVE-2026-1234", 0)
        after = conn.execute("SELECT poc_count FROM enrichments").fetchone()[0]
        check("github_zero_preserves_exploitdb_evidence", "source_integrity", after >= before,
              {"exploitdb_count": before, "after_github_zero": after})
    finally:
        conn.close()

    http = EmptyHTTP()
    with patch.object(enrichment, "init_db"), patch.object(enrichment, "get_db", return_value=EmptyConnection()):
        enrichment.run(skip_kev=True, skip_epss=True, skip_github=True,
                       skip_llm=True, skip_attention=True, session=http)
    config = enrichment.load_sources_config()
    missing_feeds = sorted(set(config.get("rss_regex_only", [])) - set(http.urls))
    check("configured_advisory_feeds_are_requested", "source_integrity", not missing_feeds,
          {"requested_feeds": len(http.urls), "unrequested_advisory_feeds": missing_feeds})

    root = Path(__file__).resolve().parents[1]
    paths = ("core/scoring.py", "core/normalizer.py", "agents/enrichment_agent.py",
             "agents/intel_agent.py", "config/sources.yaml")
    return {"scope": "Synthetic counterexamples and actual source write/orchestration paths; not predictive calibration.",
            "scoring_version": SCORING_VERSION,
            "source_sha256": {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths},
            "checks": checks, "violations": sum(not c["passed"] for c in checks)}


def main() -> int:
    result = audit()
    print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    return 1 if result["violations"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
