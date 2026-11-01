"""Tests de las fórmulas v3 — pesos y umbrales son inmutables."""
import pytest

from core.scoring import (
    calculate_hype,
    calculate_reality,
    exploit_ease,
    get_category,
    score_cve,
)

# (nombre, signals, hype esperado, reality esperado, categoría esperada)
SCORING_CASES = [
    (
        "kev_only",
        {"in_kev": True},
        0.0,
        4.0,  # 0.40*10
        "Quiet",
    ),
    (
        "epss_alto",
        {"epss": 0.9},
        0.0,
        2.25,  # 0.25*(0.9*10)
        "Quiet",
    ),
    (
        "wild_mas_ransomware",
        {"wild_confirmation": True, "ransomware_use": True},
        0.0,
        1.5,  # 0.10*10 + 0.05*10
        "Quiet",
    ),
    (
        "overhyped",
        {"cvss": 9.8, "media_score": 10.0, "branding": True, "tone_score": 9.5, "poc_score": 10.0},
        9.86,
        1.5,  # el PoC ahora cuenta como realidad (0.15*10), no sólo como hype
        "Overhyped",
    ),
    (
        "earned_the_hype",
        {
            "cvss": 9.8,
            "in_kev": True,
            "epss": 0.8,
            "wild_confirmation": True,
            "media_score": 8.0,
            "tone_score": 8.0,
            "poc_score": 5.0,
        },
        6.71,
        7.75,  # 0.40*10 + 0.25*8 + 0.15*5 + 0.10*10
        "Earned the hype",
    ),
    (
        # Un CVE en KEV con EPSS 90% tiene exploits públicos en la práctica:
        # sin el PoC daría 5.8 y quedaría "Quiet", que es el error que este
        # cambio corrige.
        "sleeper",
        {"cvss": 9.8, "in_kev": True, "epss": 0.9, "poc_score": 5.0},
        2.71,  # 0.20*9.8 + 0.15*5 (sin media)
        7.0,  # 0.40*10 + 0.25*9 + 0.15*5
        "Sleeper",
    ),
    (
        "quiet",
        {"cvss": 5.0, "media_score": 2.0, "epss": 0.1},
        1.6,
        0.25,
        "Quiet",
    ),
    (
        "cap_epss",
        {"epss": 2.5},  # 25 puntos EPSS -> cap 10
        0.0,
        2.5,
        "Quiet",
    ),
    (
        "cap_hype",
        {"cvss": 10, "media_score": 50.0, "tone_score": 50.0, "poc_score": 50.0},
        8.5,
        1.5,
        "Overhyped",
    ),
    (
        "defaults_vacios",
        {},
        0.0,
        0.0,  # sin señales no hay piso artificial
        "Quiet",
    ),
    (
        "ease_explicita",
        {"in_kev": True, "exploit_ease": 10},
        0.0,
        4.5,  # 0.40*10 + 0.05*10
        "Quiet",
    ),
]


@pytest.mark.parametrize(
    "name,signals,expected_hype,expected_reality,expected_category",
    SCORING_CASES,
    ids=[case[0] for case in SCORING_CASES],
)
def test_score_cve(name, signals, expected_hype, expected_reality, expected_category):
    result = score_cve(signals)

    assert result["hype"] == pytest.approx(expected_hype, abs=1e-9)
    assert result["reality"] == pytest.approx(expected_reality, abs=1e-9)
    assert result["category"] == expected_category


@pytest.mark.parametrize(
    "signals,expected_hype",
    [
        ({}, 0.0),
        ({"cvss": 7.5}, 1.5),
        ({"media_score": 5.0}, 1.5),
        ({"branding": True}, 1.5),
        ({"tone_score": 5.0}, 1.0),
        ({"poc_score": 5.0}, 0.75),
    ],
)
def test_hype_pesos_individuales(signals, expected_hype):
    assert calculate_hype(signals) == pytest.approx(expected_hype, abs=1e-9)


@pytest.mark.parametrize(
    "signals,expected_reality",
    [
        ({}, 0.0),
        ({"in_kev": True}, 4.0),
        ({"epss": 1.0}, 2.5),
        ({"wild_confirmation": True}, 1.0),
        ({"ransomware_use": True}, 0.5),
        ({"poc_score": 10.0}, 1.5),
        ({"exploit_ease": 10.0}, 0.5),
        ({"exploit_ease": 0.0}, 0.0),
    ],
)
def test_reality_pesos_individuales(signals, expected_reality):
    assert calculate_reality(signals) == pytest.approx(expected_reality, abs=1e-9)


@pytest.mark.parametrize(
    "vector,expected",
    [
        (None, 0.0),
        ("", 0.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 10.0),  # trivial
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 4.0),   # carrera
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 5.0),   # acceso local
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 6.0),   # pide admin
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.0),   # víctima abre algo
        ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H", 4.0),   # AC:H manda
    ],
)
def test_exploit_ease(vector, expected):
    assert exploit_ease(vector) == pytest.approx(expected, abs=1e-9)


def test_cve_kernel_con_poc_no_es_ruido():
    """Regresión CVE-2026-98432: kernel UAF remoto con 5 PoC y sin KEV.

    Antes daba 0.26: sólo el EPSS aportaba y el resto era el default de una
    complejidad que nunca se guardaba. Debe reflejar el exploit público y la
    facilidad del vector, y seguir por debajo de 5 (no hay explotación ITW).
    """
    signals = {
        "cvss": 9.8,
        "epss": 0.00457,
        "poc_score": 10.0,
        "exploit_ease": exploit_ease("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "tone_score": 5.0,
        "media_score": 10.0,
        "branding": False,
    }
    result = score_cve(signals)

    assert result["hype"] == pytest.approx(7.46, abs=0.01)
    assert result["reality"] == pytest.approx(2.01, abs=0.01)
    assert result["category"] == "Overhyped"


@pytest.mark.parametrize(
    "hype,reality,expected",
    [
        (7.0, 4.99, "Overhyped"),
        (7.0, 5.0, "Quiet"),            # reality<5 es estricto
        (6.99, 5.99, "Quiet"),
        (6.0, 6.0, "Earned the hype"),  # ambos umbrales inclusivos
        (4.99, 6.0, "Sleeper"),
        (5.0, 8.0, "Quiet"),            # Sleeper exige hype<5
        (0.0, 0.0, "Quiet"),
    ],
)
def test_categorias_bordes(hype, reality, expected):
    assert get_category(hype, reality) == expected
