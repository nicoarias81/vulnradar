"""New technical sources contribute attributable advisories, never media hype."""
import json
import pytest
from core.db import init_db, get_db
from agents.enrichment_agent import load_rss, load_sources_config
from agents.scoring_agent import score_all
from dashboard.data import load_mentions
from dashboard.screens import detail

SOURCES=[
    'https://ubuntu.com/security/notices/rss.xml',
    'https://www.debian.org/security/dsa-long',
    'https://cert.cyber.gouv.fr/avis/feed/',
    'https://www.kb.cert.org/vuls/atomfeed/',
]


class Response:
    def __init__(self,content):
        self.content=content
    def raise_for_status(self):
        pass


class HTTP:
    def __init__(self,content):
        self.content=content
        self.calls=[]
    def get(self,url,**kwargs):
        self.calls.append(url)
        return Response(self.content)


@pytest.mark.parametrize('url',SOURCES)
def test_new_source_is_enabled_and_advisory_only(tmp_path,url,monkeypatch):
    assert url in load_sources_config()['rss_regex_only']
    path=tmp_path/'advisories.db'
    init_db(path)
    monkeypatch.setattr('core.db.DB_PATH',path)
    conn=get_db(path)
    try:
        conn.execute("INSERT INTO cves(cve_id,published,description) VALUES ('CVE-2026-1234','2026-01-01','Issue')")
        conn.execute("INSERT INTO enrichments(cve_id,epss,epss_date) VALUES ('CVE-2026-1234',0,CURRENT_DATE::text)")
        # Atom content is explicitly attributed and includes a CVE in its summary.
        xml=b'''<feed xmlns="http://www.w3.org/2005/Atom"><title>Official Security</title>
        <entry><title>Vendor security update</title><link href="https://advisory.test/1"/>
        <summary>Fixes CVE-2026-1234 and CVE-2026-5678.</summary>
        <updated>2026-11-01T00:00:00Z</updated></entry></feed>'''
        http=HTTP(xml)
        assert load_rss(conn,[],regex_feeds=[url],session=http,rerank=True)=={'CVE-2026-1234':1,'CVE-2026-5678':1}
        assert http.calls==[url]
        assert load_rss(conn,[],regex_feeds=[url],session=http,rerank=True)=={}
        score_all(conn)
        score=conn.execute("SELECT hype,input_hash FROM scores WHERE cve_id='CVE-2026-1234'").fetchone()
        assert score['hype']==0
        mentions=load_mentions(conn,'CVE-2026-1234')
        assert len(mentions)==1 and mentions[0]['kind']=='advisory'
        run=conn.execute('SELECT status,details FROM source_runs WHERE source=? ORDER BY id DESC LIMIT 1',('feed:'+url,)).fetchone()
        assert run['status']=='SUCCESS' and json.loads(run['details'])['kind']=='advisory'
        conn.commit()
        html=detail({'cve':'CVE-2026-1234'})
        assert 'Technical advisory' in html
        assert 'Sources and documents' in html
        assert 'First press mention' not in html
    finally:
        conn.close()
