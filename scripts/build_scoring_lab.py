"""Populate and validate the isolated lab with real public snapshots.

Run through docker compose -f docker-compose.lab.yml run --rm runner.
Refuses other databases. Never sends alerts or calls an LLM. Resumable loads;
source snapshots, hashes, timing and validation reports live in /lab.
"""
from __future__ import annotations
import argparse
import csv
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import requests
from core.db import get_db, init_db
from core.normalizer import normalize_cve_list_v5
from core.evidence import record_run, run_source
from agents.enrichment_agent import KEV_MIRROR_URL, EPSS_URL, upsert_kev, upsert_epss, load_rss, load_sources_config, load_tone
from agents.intel_agent import EXPLOITDB_URL, sync_exploitdb, sync_ghsa, sync_sightings
from agents.scoring_agent import score_all, SCORING_VERSION
from agents.sync_agent import get_state, set_state


def cached_download(cache, name, urls, *, refresh=False):
    path = cache / name
    if not path.exists() or refresh:
        errors = []
        for url in urls:
            try:
                with requests.get(url, timeout=(10,90), stream=True) as response:
                    response.raise_for_status()
                    partial = path.with_suffix(path.suffix + '.partial')
                    with partial.open('wb') as f:
                        for chunk in response.iter_content(1024*1024):
                            f.write(chunk)
                    partial.replace(path)
                    path.with_suffix(path.suffix+'.meta.json').write_text(json.dumps({
                        'url':url,'downloaded_at':datetime.now(timezone.utc).isoformat(),
                        'last_modified':response.headers.get('Last-Modified')}),encoding='utf-8')
                    break
            except Exception as exc:
                errors.append(type(exc).__name__ + ': ' + str(exc)[:200])
        else:
            raise RuntimeError('; '.join(errors))
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):
            digest.update(chunk)
    objects=cache/'objects'
    objects.mkdir(exist_ok=True)
    archived=objects/digest.hexdigest()
    if not archived.exists():
        import shutil
        shutil.copyfile(path,archived)
    meta_path = path.with_suffix(path.suffix+'.meta.json')
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    return path, dict(meta, sha256=digest.hexdigest(),bytes=path.stat().st_size,cache_object='objects/'+digest.hexdigest())


def import_mirror(conn, mirror):
    head = subprocess.check_output(['git','-C',str(mirror),'rev-parse','HEAD'],text=True).strip()
    if get_state(conn,'lab_mirror_complete') == head:
        return {'head':head,'resumed':True,'cves':conn.execute('SELECT count(*) FROM cves').fetchone()[0]}
    columns = ['cve_id','published','last_modified','description','cvss_score','cvss_vector','cvss_severity','vendor','product','raw_json','cvss_source']
    names = ','.join(columns)
    conn.execute('CREATE TEMP TABLE lab_cve_stage AS SELECT '+names+' FROM cves WITH NO DATA')
    updates = ','.join(f'{c}=excluded.{c}' for c in columns if c!='cve_id')
    count = rejected = 0
    batch = []
    def flush():
        if not batch:
            return
        with conn._raw.cursor().copy('COPY lab_cve_stage ('+names+') FROM STDIN') as copy:
            for record in batch:
                copy.write_row([record.get(c) for c in columns])
        conn.execute('INSERT INTO cves ('+names+') SELECT '+names+' FROM lab_cve_stage ON CONFLICT(cve_id) DO UPDATE SET '+updates)
        conn.execute('TRUNCATE lab_cve_stage')
        conn.commit()
        batch.clear()
        print(f'mirror: {count:,} imported, {rejected:,} rejected',flush=True)
    # git archive reads packed objects in a stream; avoids 400k slow Windows bind opens.
    proc = subprocess.Popen(['git','-C',str(mirror),'archive',head,'cves'],stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=proc.stdout,mode='r|') as archive:
            for member in archive:
                if not member.isfile() or not Path(member.name).name.startswith('CVE-') or not member.name.endswith('.json'):
                    continue
                record = normalize_cve_list_v5(json.load(archive.extractfile(member)))
                if record is None:
                    rejected += 1
                    continue
                batch.append(record)
                count += 1
                if len(batch)>=5000:
                    flush()
        flush()
        if proc.wait()!=0:
            raise RuntimeError('git archive failed')
    finally:
        if proc.poll() is None:
            proc.terminate()
        if proc.stdout:
            proc.stdout.close()
    set_state(conn,'lab_mirror_complete',head)
    conn.commit()
    return {'head':head,'cves':count,'rejected_excluded':rejected}


def validate(conn):
    queries = {
        'coverage':"""SELECT count(*) AS cves, count(s.cve_id) AS scored,
            count(*) FILTER(WHERE c.raw_json IS NOT NULL) AS real_records,
            count(*) FILTER(WHERE e.epss IS NOT NULL) AS with_epss,
            count(*) FILTER(WHERE e.in_kev=1) AS kev,
            count(*) FILTER(WHERE e.exploitdb_poc_count>0) AS exploitdb,
            count(*) FILTER(WHERE e.wild_confirmation=1) AS trusted_wild
            FROM cves c LEFT JOIN enrichments e USING(cve_id) LEFT JOIN scores s USING(cve_id)""",
        'categories': 'SELECT category,count(*) AS n FROM scores GROUP BY category ORDER BY category',
        'source_runs': 'SELECT source,status,checked_at,version FROM source_runs ORDER BY id DESC LIMIT 50',
        'confirmed_below_tier': "SELECT count(*) AS violations FROM scores s JOIN enrichments e USING(cve_id) WHERE (e.in_kev=1 OR e.wild_confirmation=1) AND (s.reality<7 OR s.category IN ('Overhyped','Quiet','Unknown'))",
        'invalid_scores': "SELECT count(*) AS violations FROM scores WHERE NOT(hype BETWEEN 0 AND 10 AND reality BETWEEN 0 AND 10)",
        'rejected_scored': "SELECT count(*) AS violations FROM scores s JOIN cves c USING(cve_id) WHERE c.record_state='REJECTED'",
        'real_examples': """SELECT s.cve_id,s.hype,s.reality,s.category,s.exploitation_state,
            e.in_kev,e.epss,e.epss_date,e.exploitdb_poc_count FROM scores s JOIN enrichments e USING(cve_id)
            WHERE s.cve_id = ANY(?) ORDER BY s.cve_id""",
    }
    examples=['CVE-2014-0160','CVE-2017-0144','CVE-2021-44228','CVE-2023-34362','CVE-2024-3094','CVE-2024-3400','CVE-2025-24813']
    result={}
    for name,query in queries.items():
        start=time.monotonic()
        rows=conn.execute(query,(examples,) if name=='real_examples' else None).fetchall()
        result[name]={'rows':[dict(row) for row in rows],'seconds':round(time.monotonic()-start,3)}
    from scripts.audit_scoring import audit
    result['semantic_audit']=audit()
    from core.scoring import score_cve
    replayed=violations=0
    for category in ('Unknown','Watch','Quiet','Overhyped','Sleeper','Earned the hype'):
        rows=conn.execute('''SELECT input_snapshot,hype,reality,category FROM score_evaluations
            WHERE algorithm_version=? AND category=? LIMIT 25''',(SCORING_VERSION,category)).fetchall()
        for row in rows:
            actual=score_cve(json.loads(row['input_snapshot'])['signals'])
            replayed+=1
            violations+=actual != {k:row[k] for k in ('hype','reality','category')}
    result['snapshot_replay']={'evaluations':replayed,'violations':violations}
    return result


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--mirror',type=Path,required=True)
    parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--validate-only',action='store_true')
    parser.add_argument('--skip-optional',action='store_true')
    parser.add_argument('--refresh',action='store_true',help='Refresh current source aliases; previous bytes remain content-addressed')
    args=parser.parse_args()
    if os.getenv('VULNRADAR_LAB')!='1':
        raise RuntimeError('Run only in the explicitly configured scoring lab')
    conn=get_db()
    try:
        if conn.execute('SELECT current_database()').fetchone()[0]!='radar_lab':
            raise RuntimeError('Refusing to populate any database except radar_lab')
    finally:
        conn.close()
    init_db()
    conn=get_db()
    report={'captured_at':datetime.now(timezone.utc).isoformat(),'algorithm_version':SCORING_VERSION,
            'scope':'Real-data integration/volume and safety validation; not a predictive backtest.', 'snapshots':{}}
    start=time.monotonic()
    try:
        if args.validate_only and args.report.exists():
            previous=json.loads(args.report.read_text(encoding='utf-8'))
            report['snapshots']=previous.get('snapshots',{})
            report['mirror']=previous.get('mirror',{})
            report['initial_load_seconds']=previous.get('initial_load_seconds',previous.get('elapsed_seconds'))
        if not args.validate_only:
            args.cache.mkdir(parents=True,exist_ok=True)
            mirror=args.mirror
            if not (mirror/'.git').exists():
                mirror=args.cache.parent/'cvelistV5'
                if not (mirror/'.git').exists():
                    subprocess.run(['git','clone','--depth','1','https://github.com/CVEProject/cvelistV5.git',str(mirror)],check=True)
            report['mirror']=import_mirror(conn,mirror)
            for name,urls in (
                ('kev.json',[KEV_MIRROR_URL]),('epss.csv.gz',[EPSS_URL]),
                ('exploitdb.csv',[EXPLOITDB_URL,'https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv']),
            ):
                try:
                    path,meta=cached_download(args.cache,name,urls,refresh=args.refresh)
                    report['snapshots'][name]=meta
                    if name=='kev.json':
                        data=json.loads(path.read_text())
                        run_source(conn,'lab:kev',lambda:upsert_kev(conn,data['vulnerabilities']),version=data.get('catalogVersion'))
                    elif name=='epss.csv.gz':
                        with gzip.open(path,'rt') as f:
                            header=f.readline().strip()
                            metadata=dict(x.split(':',1) for x in header.lstrip('#').split(','))
                            report['snapshots'][name].update(metadata)
                            run_source(conn,'lab:epss',lambda:upsert_epss(conn,csv.DictReader(f),score_date=metadata['score_date'],model_version=metadata['model_version']),version=metadata['model_version'])
                    else:
                        run_source(conn,'lab:exploitdb',lambda:sync_exploitdb(conn,csv_text=path.read_text(encoding='utf-8')))
                    print('loaded '+name,flush=True)
                except Exception as exc:
                    report['snapshots'][name]={'error':type(exc).__name__,'message':str(exc)[:300]}
            if not args.skip_optional:
                config=load_sources_config()
                run_source(conn,'lab:rss',lambda:load_rss(conn,config.get('rss'),regex_feeds=config.get('rss_regex_only'),rerank=False,timeout=12))
                run_source(conn,'lab:ghsa',lambda:sync_ghsa(conn,pages=5,timeout=15))
                run_source(conn,'lab:circl',lambda:sync_sightings(conn,days=2,max_pages=2,timeout=15))
                run_source(conn,'lab:tone-heuristic',lambda:load_tone(conn,limit=2000,completer=lambda *a,**k:'[]'))
            conn.execute("INSERT INTO enrichments(cve_id) SELECT cve_id FROM cves ON CONFLICT(cve_id) DO NOTHING")
            conn.commit()
            scoring_start=time.monotonic()
            report['recalculated']=score_all(conn)
            report['scoring_seconds']=round(time.monotonic()-scoring_start,3)
            conn.execute('ANALYZE')
            conn.commit()
        if args.validate_only:
            # Current code can be verified against persisted snapshots without downloads.
            run_source(conn,'lab:tone-heuristic',lambda:load_tone(conn,limit=2000,completer=lambda *a,**k:'[]'))
            scoring_start=time.monotonic()
            report['recalculated']=score_all(conn)
            report['scoring_seconds']=round(time.monotonic()-scoring_start,3)
        repeat_start=time.monotonic()
        report['unchanged_recalculated']=score_all(conn)
        report['unchanged_scan_seconds']=round(time.monotonic()-repeat_start,3)
        report['validation']=validate(conn)
        report['database_bytes']=conn.execute('SELECT pg_database_size(current_database())').fetchone()[0]
        try:
            import resource
            report['peak_rss_mib']=round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,1)
        except ImportError:
            pass
        report['elapsed_seconds']=round(time.monotonic()-start,2)
        coverage=report['validation']['coverage']['rows'][0]
        report['acceptance']={
            'real_volume':coverage['real_records']>=100000,
            'epss_coverage':coverage['with_epss']>=0.90*coverage['real_records'],
            'kev_present':coverage['kev']>0,
            'curated_poc_present':coverage['exploitdb']>0,
            'unchanged_is_noop':report['unchanged_recalculated']==0,
            'snapshot_replay':report['validation']['snapshot_replay']['evaluations']>0 and report['validation']['snapshot_replay']['violations']==0,
        }
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(report,indent=2,default=str,ensure_ascii=False),encoding='utf-8')
        print(json.dumps(report,indent=2,default=str,ensure_ascii=False),flush=True)
        failed=report['validation']['semantic_audit']['violations']
        failed+=sum(report['validation'][k]['rows'][0]['violations'] for k in ('confirmed_below_tier','invalid_scores','rejected_scored'))
        failed+=sum(not passed for passed in report['acceptance'].values())
        return 1 if failed else 0
    finally:
        conn.close()


if __name__=='__main__':
    raise SystemExit(main())
