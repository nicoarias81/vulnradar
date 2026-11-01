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
    """Ordinal ladder: 8 = KEV + ransomware, 7 = KEV, 6 = working public PoC, 0-5.9 predictive.

    Each step is a different fact about the world, not a finer estimate of the
    same one:
      8  CISA says it was used in ransomware campaigns.
      7  CISA says it was exploited in the wild (KEV).
      6  Someone published code that other people starred or forked: the exploit
         exists and was corroborated, but no authority confirms wild use.
    0-5.9  Priors: EPSS probability plus, at most, +0.5 for uncorroborated repos.

    EPSS keeps its probability meaning in the separate EPSS field: adding it here
    painted 1,766 KEV entries into a 7.00-9.00 smear whose hundredths meant
    nothing, and leaving the top tier as a single 7.0 made the lists unreadable.
    """
    epss = probability(signals.get('epss')) or 0.0
    if exploitation_state(signals) == 'confirmed-exploitation':
        return 8.0 if signals.get('ransomware_use') else 7.0
    if signals.get('public_poc'):
        return 6.0
    # Raw GitHub hits stay in the predictive band: auto-generated repos appear
    # within hours of publication and mean nothing until someone stars them.
    weak_poc = min(0.5, round(0.05 * bounded(signals.get('poc_score'), 10.0), 2))
    return round(min(5.9, 5 * epss + weak_poc), 2)


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
    category = 'Unknown' if probability(signals.get('epss')) is None and not reality else get_category(hype, reality)
    if state != 'confirmed-exploitation' and reality < 6 and probability(signals.get('epss')) is not None:
        if probability(signals.get('epss')) >= 0.70:
            category = 'Watch'
    return {'hype': hype, 'reality': reality, 'category': category}
