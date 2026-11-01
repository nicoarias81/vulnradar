"""Tests for the v3 formulas — weights and thresholds are immutable."""
import pytest

from core.scoring import (
    calculate_hype,
    calculate_reality,
    exploit_ease,
    get_category,
    score_cve,
)

# (name, signals, expected hype, expected reality, expected category)
SCORING_CASES = [
    (
        "kev_only",
        {"in_kev": True},
        0.0,
        4.0,  # 0.40*10
        "Quiet",
    ),
    (
        "high_epss",
        {"epss": 0.9},
        0.0,
        2.25,  # 0.25*(0.9*10)
        "Quiet",
    ),
    (
        "wild_plus_ransomware",
        {"wild_confirmation": True, "ransomware_use": True},
        0.0,
        1.5,  # 0.10*10 + 0.05*10
        "Quiet",
    ),
    (
        "overhyped",
        {"cvss": 9.8, "media_score": 10.0, "branding": True, "tone_score": 9.5, "poc_score": 10.0},
        9.86,
        1.5,  # the PoC now counts as reality (0.15*10), not only as hype
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
        # A CVE in KEV with 90% EPSS has public exploits in practice:
        # without the PoC it would score 5.8 and land in "Quiet", which is the bug
        # this change fixes.
        "sleeper",
        {"cvss": 9.8, "in_kev": True, "epss": 0.9, "poc_score": 5.0},
        2.71,  # 0.20*9.8 + 0.15*5 (no media)
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
        {"epss": 2.5},  # 25 EPSS points -> cap 10
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
        "empty_defaults",
        {},
        0.0,
        0.0,  # without signals there is no artificial floor
        "Quiet",
    ),
    (
        "explicit_ease",
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
def test_hype_individual_weights(signals, expected_hype):
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
def test_reality_individual_weights(signals, expected_reality):
    assert calculate_reality(signals) == pytest.approx(expected_reality, abs=1e-9)


@pytest.mark.parametrize(
    "vector,expected",
    [
        (None, 0.0),
        ("", 0.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 10.0),  # trivial
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 4.0),   # race window
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 5.0),   # local access
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 6.0),   # requires admin
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.0),   # victim opens something
        ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H", 4.0),   # AC:H wins
    ],
)
def test_exploit_ease(vector, expected):
    assert exploit_ease(vector) == pytest.approx(expected, abs=1e-9)


def test_kernel_cve_with_poc_is_not_noise():
    """Regression CVE-2026-98432: remote kernel UAF with 5 PoCs and no KEV.

    It used to score 0.26: only EPSS contributed and the rest was the default of
    a complexity that was never stored. It must reflect the public exploit and
    the vector ease, and stay below 5 (there is no ITW exploitation).
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
        (7.0, 5.0, "Quiet"),            # reality<5 is strict
        (6.99, 5.99, "Quiet"),
        (6.0, 6.0, "Earned the hype"),  # both thresholds inclusive
        (4.99, 6.0, "Sleeper"),
        (5.0, 8.0, "Quiet"),            # Sleeper requires hype<5
        (0.0, 0.0, "Quiet"),
    ],
)
def test_category_boundaries(hype, reality, expected):
    assert get_category(hype, reality) == expected
