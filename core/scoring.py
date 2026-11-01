"""
Fórmulas de scoring v2 — VulnRadar
"""

def exploit_ease(vector: str | None) -> float:
    """Facilidad técnica de explotación desde el vector CVSS 3.1 (10 = trivial).

    AC manda: una condición de carrera (AC:H) no se repite igual en cada
    corrida y baja fuerte. Después se recorta si hace falta acceso local o
    adyacente, privilegios altos o interacción de la víctima.
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
    40% KEV + 25% EPSS + 15% PoC público + 10% Wild + 5% Ransomware + 5% Facilidad

    Los PoC pesan acá además de en hype: son la señal de explotabilidad más
    temprana (aparecen semanas antes de KEV y de un EPSS con señal), así que
    dejarlos sólo del lado del hype penalizaba doble a un CVE con exploit
    público. La facilidad sale del vector CVSS, no de un default fijo: el
    ``complexity_score`` que se leía antes nunca se escribía en la base y le
    regalaba 0.25 a todos los CVEs por igual.
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
