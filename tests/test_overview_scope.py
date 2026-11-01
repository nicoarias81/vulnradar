"""Operational attention survives empty publication views and has its own count."""
import re
import pytest
from core.db import init_db, get_db
from dashboard.screens import overview


@pytest.fixture
def database(tmp_path,monkeypatch):
    path=tmp_path/'overview.db'
    init_db(path)
    monkeypatch.setattr('core.db.DB_PATH',path)
    conn=get_db(path)
    yield conn
    conn.close()


def add_confirmed(conn,cve,published,product='Widget'):
    conn.execute('INSERT INTO cves(cve_id,published,description,product) VALUES (?,?,?,?)',
                 (cve,published,'Technical issue',product))
    conn.execute('INSERT INTO enrichments(cve_id,in_kev) VALUES (?,1)',(cve,))
    conn.execute("INSERT INTO scores(cve_id,hype,reality,category) VALUES (?,0,7,'Sleeper')",(cve,))
    conn.commit()


def test_attention_count_is_not_divided_by_publication_count(database):
    for cve,day in [('CVE-2000-0001','2000-01-01'),('CVE-2000-0002','2000-01-02'),('CVE-2026-0001','2026-01-01')]:
        add_confirmed(database,cve,day)
    html=overview({'category':'Sleeper','since':'2026-01-01','until':'2026-12-31'})
    assert re.search(r'acc-count">3 matching</span>',html)
    assert '3 of 1' not in html
    assert 'All publication dates;' in html
    assert 'Publication dates' in html
    assert '1–1 of 1' in html


def test_empty_publication_period_keeps_existing_attention_queue(database):
    add_confirmed(database,'CVE-2000-0001','2000-01-01')
    html=overview({'since':'2030-01-01','until':'2030-01-31'})
    assert 'CVE-2000-0001' in html
    assert '1 matching' in html
    assert 'No CVEs match these publication dates and filters.' in html
    assert 'No scores are available yet.' not in html
    assert 'autonomous worker' not in html


def test_empty_database_has_an_actual_empty_state(database):
    html=overview({'since':'2026-01-01','until':'2026-12-31'})
    assert 'No scores are available yet.' in html
    assert '0 matching' in html
    assert 'autonomous worker' not in html


def test_non_date_filters_still_scope_both_panels(database):
    add_confirmed(database,'CVE-2000-0001','2000-01-01','Widget')
    add_confirmed(database,'CVE-2000-0002','2000-01-01','Other')
    add_confirmed(database,'CVE-2026-0001','2026-01-01','Widget')
    html=overview({'since':'2026-01-01','until':'2026-12-31','product':'Widget','category':'Sleeper'})
    assert '2 matching' in html
    assert 'CVE-2000-0001' in html
    assert 'CVE-2000-0002' not in html
    assert '1–1 of 1' in html
