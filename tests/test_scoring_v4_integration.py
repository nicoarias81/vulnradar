"""End-to-end requirements from the source/scoring audit, using isolated schemas."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from agents import enrichment_agent as enrichment
from agents import intel_agent as intel
from agents import scoring_agent as scoring
from agents.alert_agent import fired_rules
from agents.sync_agent import process_cve_file
from core.db import init_db, get_db
from dashboard.data import load_actionables, load_score, hype_components

CVE='CVE-2024-12345'


@pytest.fixture
def database(tmp_path):
    path=tmp_path/'v4.db'
    init_db(path)
    conn=get_db(path)
    conn.execute("INSERT INTO cves(cve_id,published,description) VALUES (?, '2010-01-01', 'real-shaped test record')",(CVE,))
    conn.execute('INSERT INTO enrichments(cve_id) VALUES (?)',(CVE,))
    conn.commit()
    yield conn,path
    conn.close()


def fresh_epss(conn,value=0):
    enrichment.upsert_epss(conn,[{'cve':CVE,'epss':value,'percentile':0.5}])


def test_unknown_and_explicit_zero_are_distinct(database):
    conn,_=database
    scoring.score_all(conn)
    assert load_score(conn,CVE)['category']=='Unknown'
    fresh_epss(conn,0)
    scoring.score_all(conn)
    assert load_score(conn,CVE)['category']=='Quiet'


def test_trusted_exploitation_of_old_cve_is_visible_and_alertable(database):
    conn,_=database
    conn.execute('UPDATE enrichments SET wild_confirmation=1 WHERE cve_id=?',(CVE,))
    scoring.score_all(conn)
    row=load_score(conn,CVE)
    assert row['reality']>=7
    assert row['category']=='Sleeper'
    assert 'confirmed_exploitation' in fired_rules(row)
    assert [r['cve_id'] for r in load_actionables(conn,since='2026-01-01',until='2026-12-31')]==[CVE]


def test_stale_prediction_becomes_unknown(database):
    conn,_=database
    fresh_epss(conn,0.99)
    scoring.score_all(conn)
    old=(datetime.now(timezone.utc)-timedelta(days=8)).date().isoformat()
    conn.execute('UPDATE enrichments SET epss_date=? WHERE cve_id=?',(old,CVE))
    assert scoring.score_all(conn)==1
    assert load_score(conn,CVE)['category']=='Unknown'
    assert not load_actionables(conn)


def test_media_window_dedup_and_source_type_drive_actual_components(database):
    conn,_=database
    fresh_epss(conn)
    now=datetime.now(timezone.utc).date().isoformat()
    enrichment.upsert_media_mentions(conn,[
        {'cve_id':CVE,'url':'https://press.test/a?utm_source=x','title':'A concrete vulnerability','published':now},
        {'cve_id':CVE,'url':'https://syndication.test/a','title':'A concrete vulnerability','published':now},
        {'cve_id':CVE,'url':'https://vendor.test/a','title':'Vendor advisory','published':now,'kind':'advisory'},
        {'cve_id':CVE,'url':'https://press.test/old','title':'Old story','published':'2001-01-01'},
    ])
    scoring.score_all(conn)
    row=load_score(conn,CVE)
    assert row['hype']==pytest.approx(0.3)  # one distinct recent press story
    assert {r['key'] for r in hype_components(row)}=={'media','tone','branding'}
    snapshot=json.loads(row['input_snapshot'])
    assert snapshot['signals']['media_score']==0.5
    conn.execute("UPDATE media_mentions SET published='2001-01-01'")
    assert scoring.score_all(conn)==1
    assert load_score(conn,CVE)['hype']==0


def test_rejected_record_is_removed_from_current_scoring(database,tmp_path):
    conn,_=database
    fresh_epss(conn,0.9)
    scoring.score_all(conn)
    path=tmp_path/'rejected.json'
    path.write_text(json.dumps({'cveMetadata':{'cveId':CVE,'state':'REJECTED'}}))
    assert process_cve_file(path,conn) is False
    assert scoring.score_all(conn)==0
    assert load_score(conn,CVE) is None


def test_failed_kev_does_not_cancel_other_sources(database,monkeypatch):
    conn,path=database
    calls=[]
    def fail(_):
        raise RuntimeError('fixture outage')
    monkeypatch.setattr(enrichment,'load_kev',fail)
    monkeypatch.setattr(enrichment,'load_epss',lambda c:calls.append('epss') or 1)
    monkeypatch.setattr(enrichment,'load_rss',lambda *a,**k:calls.append('rss') or {})
    result=enrichment.run(db_path=path,skip_github=True,skip_llm=True,skip_attention=True)
    assert calls==['epss','rss']
    assert result['errors']==['kev']
    assert conn.execute("SELECT status FROM source_runs WHERE source='kev' ORDER BY id DESC LIMIT 1").fetchone()[0]=='ERROR'


def test_ungrounded_model_brand_is_rejected_but_grounded_brand_is_preserved(database):
    conn,_=database
    def complete(*a,**k):
        return json.dumps([{'cve_id':CVE,'tone_score':4,'branding':True,'brand_name':'GroundShell'}])
    result=enrichment.analyze_tone_batch([{'cve_id':CVE,'title':'Vulnerability dubbed GroundShell'}],completer=complete)
    enrichment.upsert_tone(conn,result)
    enrichment.upsert_tone(conn,[{'cve_id':CVE,'tone_score':1,'branding':False,'brand_name':None,'source':'heuristic'}])
    assert conn.execute('SELECT brand_name FROM enrichments WHERE cve_id=?',(CVE,)).fetchone()[0]=='GroundShell'
    assert conn.execute("SELECT count(*) FROM evidence WHERE source='tone'").fetchone()[0]>=1


def test_input_changes_are_auditable_when_rounded_score_does_not_change(database):
    conn,_=database
    fresh_epss(conn,0.00001)
    scoring.score_all(conn)
    fresh_epss(conn,0.00002)
    scoring.score_all(conn)
    assert conn.execute('SELECT count(*) FROM score_evaluations WHERE cve_id=?',(CVE,)).fetchone()[0]==2
    assert conn.execute('SELECT count(*) FROM score_history WHERE cve_id=?',(CVE,)).fetchone()[0]==1


def test_untrusted_sighting_is_retained_without_claiming_confirmed_exploitation(database,monkeypatch):
    conn,_=database
    monkeypatch.delenv('CIRCL_TRUSTED_AUTHORS',raising=False)
    monkeypatch.setattr(intel,'fetch_sightings_page',lambda *a,**k:{'metadata':{'count':1},'data':[
        {'uuid':'fixture','type':'exploited','vulnerability':CVE,'author':{'uuid':'untrusted'},'source':'https://example.test/report'}]})
    assert intel.sync_sightings(conn)['cves_explotados']==0
    assert conn.execute("SELECT trusted FROM evidence WHERE source='circl'").fetchone()[0] is False
    assert conn.execute('SELECT wild_confirmation FROM enrichments WHERE cve_id=?',(CVE,)).fetchone()[0]==0


def test_database_rejects_non_finite_scores(database):
    conn,_=database
    with pytest.raises(Exception):
        conn.execute('INSERT INTO scores(cve_id,hype,reality,category) VALUES (?, ?, ?, ?)',(CVE,float('nan'),1,'Quiet'))
    conn.rollback()


def test_ghsa_backfill_advances_while_recent_pages_refresh(database,monkeypatch):
    conn,_=database
    calls=[]
    def fetch(*,page=1,**kwargs):
        calls.append(page)
        return [{'cve_id':CVE,'cvss_severities':{'cvss_v3':{'score':7.5,'vector_string':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}},'severity':'high'}]
    monkeypatch.setattr(intel,'fetch_ghsa_page',fetch)
    intel.sync_ghsa(conn,pages=1,advance_cursor=True)
    intel.sync_ghsa(conn,pages=1,advance_cursor=True)
    assert calls==[1,2,1,3]
    row=conn.execute('SELECT cvss_score,cvss_vector,cvss_source FROM cves WHERE cve_id=?',(CVE,)).fetchone()
    assert row[0]==7.5 and row[1].startswith('CVSS:3.1/') and row[2]=='ghsa'


def test_watch_does_not_trigger_baseless_hype_alarm(database):
    conn,_=database
    fresh_epss(conn,0.95)
    conn.execute('UPDATE enrichments SET tone_score=9 WHERE cve_id=?',(CVE,))
    scoring.score_all(conn)
    row=load_score(conn,CVE)
    assert row['category']=='Watch'
    assert fired_rules(row)==['watch']
