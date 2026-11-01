"""Press coverage includes publisher-provided article content, not guessed IDs."""
import json
import pytest
from agents.enrichment_agent import (parse_feed,collect_mentions,rerank_entries,
    mentions_from_rerank,build_rerank_prompt,load_sources_config,_reranked_urls,_mark_reranked)

PRESS=[
    'https://www.theregister.com/security/headlines.atom',
    'https://www.infosecurity-magazine.com/rss/news/',
    'https://securityaffairs.com/feed',
    'https://www.csoonline.com/feed/',
    'https://unaaldia.hispasec.com/feed',
]


@pytest.mark.parametrize('url',PRESS)
def test_specialist_press_is_enabled_as_press_not_advisory(url):
    config=load_sources_config()
    assert url in config['rss']
    assert url not in config['rss_regex_only']


def article():
    xml=b'''<feed xmlns="http://www.w3.org/2005/Atom"><title>Example Press</title>
    <entry><title>New flaw receives extensive attention</title>
    <link href="https://press.test/news/1"/>
    <summary>A short lead without an identifier.</summary>
    <content type="html">&lt;p&gt;Article body marker: CVE-2026-1234 and CVE-2026-5678.
    CVE-2026-1234 is repeated.&lt;/p&gt;</content>
    <updated>2026-11-01T00:00:00Z</updated></entry></feed>'''
    return parse_feed(xml)


def test_atom_body_recovers_explicit_cves_without_retaining_article_text():
    entries=article()
    assert entries[0]['cve_ids']==['CVE-2026-1234','CVE-2026-5678']
    mentions=collect_mentions(entries)
    assert {m['cve_id'] for m in mentions}=={'CVE-2026-1234','CVE-2026-5678'}
    assert len(mentions)==2
    assert 'Article body marker' not in json.dumps(entries)
    assert all(m['source']=='Example Press' for m in mentions)


def test_content_encoded_with_a_short_description_is_also_read():
    xml=b'''<rss xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel>
    <title>News</title><item><title>Urgent patch</title><link>https://press.test/a</link>
    <description>Lead without CVEs</description>
    <content:encoded><![CDATA[<p>CVE&#45;2026&#45;4321 affects the product.</p>
    <script>"CVE-2026-9999"</script><style>/* CVE-2026-8888 */</style>
    <!-- CVE-2026-7777 -->]]></content:encoded></item></channel></rss>'''
    assert {m['cve_id'] for m in collect_mentions(parse_feed(xml))}=={'CVE-2026-4321'}


def test_llm_sees_body_identifiers_but_cannot_invent_another_one():
    entries=article()
    assert 'explicit_cves="CVE-2026-1234,CVE-2026-5678"' in build_rerank_prompt(entries)
    grounded=rerank_entries(entries,completer=lambda _:'[{"i":1,"cve_id":"CVE-2026-1234","relevant":true}]')
    assert grounded[0]['cve_id']=='CVE-2026-1234'
    assert len(mentions_from_rerank(entries,grounded))==2
    invented=rerank_entries(entries,completer=lambda _:'[{"i":1,"cve_id":"CVE-2026-9999","relevant":true}]')
    assert invented[0]['cve_id'] is None


def test_old_extractor_cache_does_not_hide_new_article_body_evidence(tmp_path):
    from core.db import get_db,init_db
    path=tmp_path/'press-cache.db'
    init_db(path)
    conn=get_db(path)
    try:
        entries=article()
        url=entries[0]['url']
        conn.execute('INSERT INTO reranked_urls(url) VALUES (?)',(url,))
        assert _reranked_urls(conn,entries)==set()
        _mark_reranked(conn,entries,[{'cve_id':'CVE-2026-1234','relevant':True}])
        assert _reranked_urls(conn,entries)=={url}
    finally:
        conn.close()
