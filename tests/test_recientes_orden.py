"""The recent table sorts by publication date, not by computation."""


def test_recent_sorts_by_publication_and_not_by_calculation():
    """A CVE without a date cannot sneak above a published one.

    With `coalesce(published, calculated_at)` the day of a stub without a date
    became today, tied with the ones published that day, and the alphabetical
    tiebreak pushed 2023 CVEs to the top of the home page.
    """
    from dashboard.data import _order_sql

    sql = _order_sql("published")

    assert "c.published DESC NULLS LAST" in sql
    assert "calculated_at" not in sql
