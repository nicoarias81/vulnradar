"""Mentions imported from the local backfill must carry kind/story_key/domain.

Without kind='press' the scoring ignores them and imported press never moves Hype.
"""
import pytest

from core.db import get_db, init_db
from scripts.import_menciones import importar

CVE = "CVE-2026-4242"


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "mentions.db"
    init_db(path)
    conn = get_db(path)
    conn.execute(
        "INSERT INTO cves(cve_id, published, description) VALUES (?, '2026-10-01', 'test')",
        (CVE,),
    )
    conn.execute("INSERT INTO enrichments(cve_id) VALUES (?)", (CVE,))
    conn.commit()
    yield conn
    conn.close()


def row(url, title):
    return {"cve_id": CVE, "url": url, "title": title, "source": "Example", "published": "2026-10-30"}


def test_imported_mentions_are_press_with_story_key_and_domain(database):
    conn = database
    importar(conn, [row("https://www.example.com/a", "Flaw under heavy fire")])

    kind, story_key, domain = conn.execute(
        "SELECT kind, story_key, domain FROM media_mentions WHERE cve_id=?", (CVE,)
    ).fetchone()
    assert kind == "press"
    assert story_key and len(story_key) == 64
    assert domain == "www.example.com"


def test_same_headline_shares_story_key_across_outlets(database):
    conn = database
    importar(conn, [
        row("https://a.example.com/1", "Flaw under heavy fire"),
        row("https://b.example.com/2", "Flaw   under HEAVY fire!"),
    ])
    keys = [r[0] for r in conn.execute(
        "SELECT story_key FROM media_mentions WHERE cve_id=?", (CVE,)
    ).fetchall()]
    assert len(keys) == 2 and len(set(keys)) == 1


def test_advisory_feed_mention_is_not_counted_as_press(database):
    conn = database
    importar(conn, [row("https://cvefeed.io/vuln/detail/CVE-2026-4242", "Advisory entry")])
    kind = conn.execute(
        "SELECT kind FROM media_mentions WHERE cve_id=?", (CVE,)
    ).fetchone()[0]
    assert kind == "advisory"
