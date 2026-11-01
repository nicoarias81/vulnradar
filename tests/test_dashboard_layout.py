"""User-facing layout contracts and independently paginated attention results."""
from html.parser import HTMLParser
from urllib.parse import urlsplit,parse_qs
import re
import pytest
from core.db import init_db,get_db
from dashboard.data import load_actionables
from dashboard.screens import overview
from dashboard.markup import detail_html


class Links(HTMLParser):
    def __init__(self,html):
        super().__init__()
        self.links=[]
        self.feed(html)
    def handle_starttag(self,tag,attrs):
        if tag=='a':self.links.append(dict(attrs))


@pytest.fixture
def database(tmp_path,monkeypatch):
    path=tmp_path/'layout.db'
    init_db(path)
    monkeypatch.setattr('core.db.DB_PATH',path)
    conn=get_db(path)
    for i in range(14):
        cve=f'CVE-2026-{1000+i}'
        conn.execute("INSERT INTO cves(cve_id,published,description,product,cvss_severity) VALUES (?,'2026-10-20','Widget issue','Widget','CRITICAL')",(cve,))
        conn.execute('INSERT INTO enrichments(cve_id,in_kev) VALUES (?,1)',(cve,))
        conn.execute("INSERT INTO scores(cve_id,hype,reality,category) VALUES (?,0,7,'Sleeper')",(cve,))
    conn.commit()
    yield conn
    conn.close()


def attention_ids(html):
    table=re.search(r'<table class="table acc-table">(.*?)</table>',html,re.S).group(1)
    return [a['href'].split('=')[-1] for a in Links(table).links]


def test_attention_sql_pages_have_no_duplicates_and_last_page_is_partial(database):
    first=load_actionables(database,limit=6,offset=0)
    second=load_actionables(database,limit=6,offset=6)
    last=load_actionables(database,limit=6,offset=12)
    assert [len(first),len(second),len(last)]==[6,6,2]
    assert len({r['cve_id'] for r in first+second+last})==14


def test_attention_navigation_preserves_filters_and_publication_page(database):
    params={'since':'2026-10-01','until':'2026-10-31','category':'Sleeper','severity':'CRITICAL','product':'Widget','q':'Widget','page':'1','attention_page':'1'}
    html=overview(params)
    next_link=next(a for a in Links(html).links if a.get('aria-label')=='Next attention page')
    query=parse_qs(urlsplit(next_link['href']).query)
    assert query=={k:[v] for k,v in dict(params,attention_page='2').items()}
    assert urlsplit(next_link['href']).fragment=='attention-queue'
    assert '7–12 of 14' in html
    publication_next=next(a for a in Links(html).links if parse_qs(urlsplit(a.get('href','')).query).get('page')==['2'])
    assert parse_qs(urlsplit(publication_next['href']).query)['attention_page']==['1']


@pytest.mark.parametrize('value',['invalid','-5','0','1','99999'])
def test_attention_page_input_is_clamped_and_changes_real_rows(database,value):
    html=overview({'since':'2026-10-01','until':'2026-10-31','attention_page':value})
    expected=2 if value=='99999' else 1 if value=='1' else 0
    ids=attention_ids(html)
    assert ids[0]==f'CVE-2026-{1000+expected*6}'
    assert len(ids)==(2 if expected==2 else 6)
    if expected==2:
        assert not any(a.get('aria-label')=='Next attention page' for a in Links(html).links)


def test_home_has_no_featured_reference_shortcuts(database):
    html=overview({})
    assert 'Dated reference cases:' not in html
    assert 'overview-top' in html


def test_detail_places_primary_cards_before_collapsed_prose_and_references():
    html=detail_html(cve_id='CVE-2026-1234',description='Long description. '*300,
        badges='',bars='<div>Component chart</div>',hype=7,reality=8,category='Earned the hype',
        events='Source events',mentions='Documents',pocs_html='Public exploits',poc_count=0,
        now='2026-11-01',timeline='<svg>History chart</svg>',
        evidence_context='<div>Dated case notes</div>')
    assert html.index('class="detail-grid"')<html.index('id="evidence-context-panel"')
    assert html.index('id="score-history"')<html.index('Dated case notes')
    assert '<details class="card context-disclosure" id="evidence-context-panel">' in html
    assert '<details class="card context-disclosure" id="source-event-timeline">' in html
    assert 'Read full description' in html
    assert 'Long description. '*300 in html
    assert 'detail-summary' in html and 'detail-components' in html and 'detail-sources' in html
