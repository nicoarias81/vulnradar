"""Dated source claims must not be flattened into worldwide exploitation claims."""
from html.parser import HTMLParser
import pytest
from core.reference_cases import case_for_cve,match_case
from dashboard.assessment import assessment,assessment_html
from dashboard.theme import CATEGORY_DETAIL
from dashboard.markup import legend_html
from core.db import init_db,get_db
from dashboard.data import find_cve_id,load_scores,load_daily_averages
from dashboard.screens import detail


def test_php_reference_preserves_publication_order_and_later_confirmation():
    early=case_for_cve('CVE-2026-109618',asof='2026-10-24')
    assert [n['kind'] for n in early['notes']]==['attempts']
    withdrawn=case_for_cve('CVE-2026-109618',asof='2026-10-25')
    assert {n['kind'] for n in withdrawn['notes']}=={'attempts','retraction'}
    # CrowdSec's 21-25 observation window was published on the 26th, not the 25th.
    assert not any(n['source']=='CrowdSec' for n in withdrawn['notes'])
    current=case_for_cve('CVE-2026-109619',asof='2026-11-01')
    kinds={n['kind'] for n in current['notes']}
    assert {'retraction','catalog_confirmation','limited_telemetry','confirmed_campaign'}<=kinds
    assert current['notes'][-1]['available_on']=='2026-10-29'
    assert 'PAN-OS' in current['notes'][-1]['scope']


def test_kernel_reference_does_not_invent_confirmed_activity():
    assert case_for_cve('CVE-2026-98432',asof='2026-10-30')['notes']==[]
    current=case_for_cve('CVE-2026-98432',asof='2026-11-01')
    assert {n['kind'] for n in current['notes']}=={'technical_potential'}
    view=assessment({'cve_id':'CVE-2026-98432','in_kev':0,'wild_confirmation':0},[],asof='2026-11-01')
    assert view['activity'].startswith('No trusted exploitation observation')
    assert 'not quantified' in view['scope']


def test_curated_notes_do_not_override_live_flags():
    # Even a case with historical confirmation cannot silently flip current inputs.
    row={'cve_id':'CVE-2026-109618','in_kev':0,'wild_confirmation':0}
    view=assessment(row,[],asof='2026-11-01')
    assert view['activity'].startswith('No trusted exploitation observation')
    assert any(n['kind']=='confirmed_campaign' for n in view['reference']['notes'])
    assert view['reference_coverage_gap'] is True
    assert row=={'cve_id':'CVE-2026-109618','in_kev':0,'wild_confirmation':0}


def test_known_exploitation_does_not_establish_global_scale():
    view=assessment({'cve_id':'CVE-2026-0001','in_kev':1},[],asof='2026-11-01')
    assert 'KEV' in view['activity']
    assert 'not quantified' in view['scope'] and 'victim count' in view['scope']
    assert 'does not establish widespread compromise' in CATEGORY_DETAIL['Earned the hype']


def test_recent_coverage_counts_documents_stories_and_domains_separately():
    docs=[
        {'kind':'press','published':'2026-10-20','url':'https://one.test/a','story_key':'same'},
        {'kind':'press','published':'2026-10-21','url':'https://www.two.test/b','story_key':'same'},
        {'kind':'press','published':'2026-09-01','url':'https://old.test/a','story_key':'old'},
        {'kind':'press','published':'2026-11-02','url':'https://future.test/a','story_key':'future'},
        {'kind':'advisory','published':'2026-10-21','url':'https://vendor.test/a','story_key':'notice'},
    ]
    view=assessment({},docs,asof='2026-11-01')
    assert view['attention']=={'stories':1,'documents':2,'domains':['one.test','two.test']}


def test_reference_aliases_are_specific_and_results_are_not_mutable_shared_state():
    assert match_case(' PHP2Shell ')['cves']==['CVE-2026-109618','CVE-2026-109619']
    assert match_case('kernel') is None  # Do not map every kernel RCE to one record.
    ref=case_for_cve('CVE-2026-109618',asof='2026-11-01')
    ref['notes'].clear()
    assert case_for_cve('CVE-2026-109618',asof='2026-11-01')['notes']
    assert case_for_cve('CVE-2099-1234') is None
    old=case_for_cve('CVE-2026-109618',asof='2027-01-01')
    assert old['stale_review'] is True and old['asof']=='2026-11-01'


def test_public_context_escapes_untrusted_fields_and_shows_source_dates():
    html=assessment_html({'cve_id':'CVE-2026-109618','in_kev':1,'calculated_at':'<img src=x>'},[],asof='2026-11-01')
    assert '<img src=x>' not in html and '&lt;img src=x&gt;' in html
    assert '2026-10-25' in html and '2026-10-29' in html
    assert 'does not establish' in html
    assert 'not a measurement of exploitation across all PHP installations' in html


def test_legend_has_descriptive_labels_instead_of_hype_merit_verdict():
    html=legend_html()
    assert 'High attention + observed exploitation' in html
    assert 'Earned the hype' not in html
    assert 'Observed exploitation + lower recent attention' in html


def test_named_php_case_search_returns_both_cves_without_alias_in_descriptions(tmp_path,monkeypatch):
    path=tmp_path/'cases.db'
    init_db(path)
    monkeypatch.setattr('core.db.DB_PATH',path)
    conn=get_db(path)
    try:
        assert find_cve_id(conn,'kernel ipv4 rce') is None
        for cve in ('CVE-2026-109618','CVE-2026-109619','CVE-2026-98432'):
            conn.execute("INSERT INTO cves(cve_id,published,description) VALUES (?,'2026-10-21','Memory issue')",(cve,))
            conn.execute('INSERT INTO enrichments(cve_id,in_kev) VALUES (?,1)',(cve,))
            conn.execute("INSERT INTO scores(cve_id,hype,reality,category) VALUES (?,8,8,'Earned the hype')",(cve,))
        conn.commit()
        assert find_cve_id(conn,'php2shell') is None  # No arbitrary choice of one CVE.
        assert find_cve_id(conn,'kernel ipv4 rce')=='CVE-2026-98432'
        rows=load_scores(conn,query='PHP2Shell')
        assert {r['cve_id'] for r in rows}=={'CVE-2026-109618','CVE-2026-109619'}
        assert sum(p['n'] for p in load_daily_averages(conn,query='php2shell'))==2
        html=detail({'cve':'CVE-2026-109618'})
        assert 'Evidence in context' in html and 'Known scale' in html
        assert 'Dated reference: PHP2Shell' in html
        assert 'HIGH ATTENTION + OBSERVED EXPLOITATION' in html
        assert 'EARNED THE HYPE' not in html
        assert 'Page generated:' in html
    finally:
        conn.close()
