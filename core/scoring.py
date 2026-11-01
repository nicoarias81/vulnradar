"""
Scoring v2 formulas — VulnRadar
"""

def exploit_ease(vector: str | None) -> float:
    """Technical ease of exploitation from the CVSS 3.1 vector (10 = trivial).

    AC rules: a race condition (AC:H) does not repeat the same on every run
    and drops hard. Then it is capped if local or adjacent access, high
    privileges or victim interaction are required.
    """
    if not vector:
        return 0.0
    v = vector.upper()
    ease = 4.0 if "AC:H" in v else 10.0
    if "AV:L" in v or "AV:A" in v or "AV:P" in v:
        ease = min(ease, 5.0)
    if "PR:H" in v:
        ease = min(ease, 6.0)
    if "UI:R" in v:
        ease = min(ease, 7.0)
    return ease


def calculate_reality(signals: dict) -> float:
    """
    Reality v3
    40% KEV + 25% EPSS + 15% public PoC + 10% Wild + 5% Ransomware + 5% Ease

    PoCs weigh in here on top of hype: they are the earliest exploitability
    signal (they show up weeks before KEV and before an EPSS with signal), so
    leaving them only on the hype side double-penalized a CVE with a public
    exploit. Ease comes from the CVSS vector, not from a fixed default: the
    ``complexity_score`` read before was never written to the database and
    handed 0.25 to every CVE alike.
    """
    kev = 10.0 if signals.get("in_kev") else 0.0
    epss = min(signals.get("epss", 0) * 10, 10.0)
    poc = min(signals.get("poc_score", 0), 10.0)
    wild = 10.0 if signals.get("wild_confirmation") else 0.0
    ransomware = 10.0 if signals.get("ransomware_use") else 0.0
    ease = signals.get("exploit_ease", 0.0)

    return round(
        0.40 * kev +
        0.25 * epss +
        0.15 * poc +
        0.10 * wild +
        0.05 * ransomware +
        0.05 * ease,
        2
    )


def calculate_hype(signals: dict) -> float:
    """
    Hype v2
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
