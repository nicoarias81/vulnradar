"""The Umami snippet is not injected into views that auto-refresh.

/soc reloads every 8s through `<meta http-equiv="refresh">`: if it tracked, every
reload would add a visit and the site metrics would be inflated (measured: 167 out
of 396 events were panel reloads).
"""
from dashboard.markup import document

SCRIPT = "analytics.munalabs.eu/script.js"


def test_normal_page_tracks():
    assert SCRIPT in document("<p>x</p>")


def test_view_with_auto_refresh_does_not_track():
    assert SCRIPT not in document("<p>x</p>", refresh=8)


def test_explicit_track_wins_over_refresh():
    assert SCRIPT in document("<p>x</p>", refresh=8, track=True)
    assert SCRIPT not in document("<p>x</p>", track=False)
