"""
Fórmulas de scoring v2 — Humo vs Miedo
"""

def calculate_reality(signals: dict) -> float:
    """
    Reality (Miedo) v2
    45% KEV + 25% EPSS + 20% Wild + 5% Ransomware + 5% Complexity
    """
    kev = 10.0 if signals.get("in_kev") else 0.0
    epss = min(signals.get("epss", 0) * 10, 10.0)
    wild = 10.0 if signals.get("wild_confirmation") else 0.0
    ransomware = 10.0 if signals.get("ransomware_use") else 0.0
    complexity = signals.get("complexity_score", 5.0)  # 0-10, default medio

    return round(
        0.45 * kev +
        0.25 * epss +
        0.20 * wild +
        0.05 * ransomware +
        0.05 * complexity,
        2
    )


def calculate_hype(signals: dict) -> float:
    """
    Hype (Humo) v2
    20% CVSS + 30% Media + 15% Branding + 20% Tone + 15% PoCs
    """
    cvss = signals.get("cvss", 0)
    media = min(signals.get("media_score", 0), 10.0)
    branding = 10.0 if signals.get("branding") else 0.0
    tone = min(signals.get("tone_score", 0), 10.0)
    pocs = min(signals.get("poc_score", 0), 10.0)

    return round(
        0.20 * cvss +
        0.30 * media +
        0.15 * branding +
        0.20 * tone +
        0.15 * pocs,
        2
    )


def get_category(hype: float, reality: float) -> str:
    if hype >= 7.0 and reality < 5.0:
        return "Overhyped"
    elif hype >= 6.0 and reality >= 6.0:
        return "Earned the hype"
    elif reality >= 6.0 and hype < 5.0:
        return "Sleeper"
    else:
        return "Quiet"


def score_cve(signals: dict) -> dict:
    hype = calculate_hype(signals)
    reality = calculate_reality(signals)
    category = get_category(hype, reality)
    return {
        "hype": hype,
        "reality": reality,
        "category": category
    }
