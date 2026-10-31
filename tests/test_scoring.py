"""Tests de las fórmulas v2 — pesos y umbrales son inmutables."""
import pytest

from core.scoring import calculate_hype, calculate_reality, get_category, score_cve

# (nombre, signals, hype esperado, reality esperado, categoría esperada)
SCORING_CASES = [
    (
        "kev_only",
        {"in_kev": True},
        0.0,
        4.75,  # 0.45*10 + 0.05*5 (complexity default)
        "Quiet",
    ),
    (
        "epss_alto",
        {"epss": 0.9},
        0.0,
        2.5,  # 0.25*(0.9*10) + 0.05*5
        "Quiet",
    ),
    (
        "wild_mas_ransomware",
        {"wild_confirmation": True, "ransomware_use": True},
        0.0,
        2.75,  # 0.20*10 + 0.05*10 + 0.05*5
        "Quiet",
    ),
    (
        "overhyped",
        {"cvss": 9.8, "media_score": 10.0, "branding": True, "tone_score": 9.5, "poc_score": 10.0},
        9.86,
        0.25,
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
        8.75,
        "Earned the hype",
    ),
    (
        "sleeper",
        {"cvss": 9.8, "in_kev": True, "epss": 0.9},
        1.96,
        7.0,
        "Sleeper",
    ),
    (
        "quiet",
        {"cvss": 5.0, "media_score": 2.0, "epss": 0.1},
        1.6,
        0.5,
        "Quiet",
    ),
    (
        "cap_epss",
        {"epss": 2.5},  # 25 puntos EPSS -> cap 10
        0.0,
        2.75,
        "Quiet",
    ),
    (
        "cap_hype",
        {"cvss": 10, "media_score": 50.0, "tone_score": 50.0, "poc_score": 50.0},
        8.5,
        0.25,
        "Overhyped",
    ),
    (
        "defaults_vacios",
        {},
        0.0,
        0.25,  # sólo complexity default
        "Quiet",
    ),
    (
        "complexity_explicita",
        {"in_kev": True, "complexity_score": 10},
        0.0,
        5.0,  # 0.45*10 + 0.05*10 (sin default de complexity)
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
        ({}, 0.25),
        ({"in_kev": True}, 4.75),
        ({"epss": 1.0}, 2.75),
        ({"wild_confirmation": True}, 2.25),
        ({"ransomware_use": True}, 0.75),
        ({"complexity_score": 0.0}, 0.0),
    ],
)
def test_reality_pesos_individuales(signals, expected_reality):
    assert calculate_reality(signals) == pytest.approx(expected_reality, abs=1e-9)


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
