"""Scoring v4: explicit evidence tiers; ordinal indices, never probabilities."""
from __future__ import annotations
import math


def bounded(value, high=10.0, default=0.0):
    try:
        value = float(value)
    except (ValueError, TypeError):
        return default
    return min(high, max(0.0, value)) if math.isfinite(value) else default


def exploit_ease(vector: str | None) -> float:
    if not isinstance(vector, str):
        return 0.0
    parts = vector.upper().split('/')
    if parts[0] not in ('CVSS:3.0', 'CVSS:3.1', 'CVSS:4.0'):
        return 0.0
    try:
        pairs = [part.split(':') for part in parts[1:]]
        if any(len(p) != 2 for p in pairs):
            return 0.0
        metrics = dict(pairs)
        if len(metrics) != len(pairs):
            return 0.0
    except (ValueError, TypeError):
        return 0.0
    allowed = {'AV': 'NALP', 'AC': 'LH', 'PR': 'NLH', 'UI': 'NPA' if parts[0] == 'CVSS:4.0' else 'NR'}
    if parts[0] == 'CVSS:4.0':
        allowed.update({'AT': 'NP', **{k: 'HLN' for k in ('VC','VI','VA','SC','SI','SA')}})
    else:
        allowed.update({'S': 'UC', 'C': 'HLN', 'I': 'HLN', 'A': 'HLN'})
    if any(metrics.get(k) not in list(v) for k, v in allowed.items()):
        return 0.0
    ease = 4.0 if metrics['AC'] == 'H' or metrics.get('AT') == 'P' else 10.0
    if metrics['AV'] != 'N':
        ease = min(ease, 5.0)
    if metrics['PR'] == 'H':
        ease = min(ease, 6.0)
    if metrics['PR'] == 'L':
        ease = min(ease, 8.0)
    if metrics['UI'] != 'N':
        ease = min(ease, 6.0 if metrics['UI'] == 'A' else 7.0)
    return ease


def exploitation_state(signals: dict) -> str:
    if signals.get('in_kev') or signals.get('wild_confirmation'):
        return 'confirmed-exploitation'
    if signals.get('public_poc'):
        return 'public-poc'
    if signals.get('epss') is None:
        return 'unknown'
    return 'no-known-exploitation'


def probability(value):
    try:
        value = float(value)
    except (ValueError, TypeError):
        return None
    return value if math.isfinite(value) and 0 <= value <= 1 else None


def calculate_reality(signals: dict) -> float:
    """Ordinal tiers: confirmed exploitation 7-8; predictive evidence 0-5.9.

    The floors are product safety rules, not fitted/calibrated probabilities.
    EPSS retains its probability meaning only in the separate EPSS field: adding
    it here duplicated the signal and painted 1,766 KEV entries into a 7.00-9.00
    smear whose hundredths meant nothing. Ties are broken where the list is read
    (epss DESC, kev date DESC), not by inflating the score.
    Ease and repository popularity do not add correlated predictive evidence.
    """
    epss = probability(signals.get('epss')) or 0.0
    if exploitation_state(signals) == 'confirmed-exploitation':
        return 7.0 + (1.0 if signals.get('ransomware_use') else 0.0)
    # Public exploit code is capability evidence, graded by provenance:
    # ExploitDB/validated repos are strong (+1.0); raw GitHub hits are weak
    # (up to +0.5 on the 0-10 poc_score scale) because auto-generated repos appear
    # within hours of publication. Before this, poc_score was computed and never
    # read by the score: 25,189 CVEs had public repos and the public-PoC inputs
    # (exploitdb/validated counts) were 0 everywhere, so every prediction read 0.0.
    strong_poc = 1.0 if signals.get('public_poc') else 0.0
    weak_poc = min(0.5, round(0.05 * bounded(signals.get('poc_score'), 10.0), 2))
    return round(min(5.9, 5 * epss + strong_poc + weak_poc), 2)


def calculate_hype(signals: dict) -> float:
    """Attention index: 60% recent media, 25% aggregate tone, 15% grounded brand.

    No CVSS or repository count: technical severity and candidate exploit
    popularity remain separate dimensions. The index is not measured exaggeration.
    """
    return round(0.60 * bounded(signals.get('media_score'))
                 + 0.25 * bounded(signals.get('tone_score'))
                 + (1.5 if signals.get('branding') else 0.0), 2)


def get_category(hype: float, reality: float) -> str:
    if reality >= 6:
        return 'Earned the hype' if hype >= 6 else 'Sleeper'
    if hype >= 7 and reality < 5:
        return 'Overhyped'
    return 'Quiet'


def score_cve(signals: dict) -> dict:
    hype, reality = calculate_hype(signals), calculate_reality(signals)
    state = exploitation_state(signals)
    category = 'Unknown' if probability(signals.get('epss')) is None and state != 'confirmed-exploitation' else get_category(hype, reality)
    if state != 'confirmed-exploitation' and probability(signals.get('epss')) is not None:
        if probability(signals.get('epss')) >= 0.70 or signals.get('public_poc'):
            category = 'Watch'
    return {'hype': hype, 'reality': reality, 'category': category}
