"""Dated editorial reference notes, separate from live source/scoring inputs."""
from __future__ import annotations
from copy import deepcopy
from datetime import date, datetime, timezone
from functools import lru_cache
import json
from pathlib import Path

PATH = Path(__file__).resolve().parents[1]/'config'/'reference_cases.json'


@lru_cache(maxsize=1)
def _cases():
    cases=json.loads(PATH.read_text(encoding='utf-8'))['cases']
    for case in cases:
        date.fromisoformat(case['reviewed_on'])
        for note in case['notes']:
            date.fromisoformat(note['available_on'])
            if not note['url'].startswith('https://'):
                raise ValueError('Reference source must use HTTPS')
    return cases


def match_case(query):
    text=' '.join(str(query or '').casefold().split())
    for case in _cases():
        if text in {case['id'].casefold(),case['name'].casefold(),*(a.casefold() for a in case['aliases'])}:
            return deepcopy(case)
    return None


def case_for_cve(cve_id, *, asof=None):
    cutoff=date.fromisoformat(asof) if asof else datetime.now(timezone.utc).date()
    for case in _cases():
        if cve_id in case['cves']:
            result=deepcopy(case)
            result['requested_asof']=cutoff.isoformat()
            result['stale_review']=cutoff>date.fromisoformat(case['reviewed_on'])
            cutoff=min(cutoff,date.fromisoformat(case['reviewed_on']))
            result['asof']=cutoff.isoformat()
            result['notes']=sorted((n for n in result['notes'] if date.fromisoformat(n['available_on'])<=cutoff),key=lambda n:n['available_on'])
            return result
    return None
