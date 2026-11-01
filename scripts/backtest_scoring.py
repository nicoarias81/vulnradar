"""Historical EPSS ranking against subsequent KEV additions (a limited proxy).

Snapshots at t and t+30 prevent using contemporaneous KEV as a future label.
This does not label every exploited CVE or prove probability calibration.
"""
from __future__ import annotations
import argparse
import csv
import gzip
import json
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.build_scoring_lab import cached_download
from core.scoring import calculate_reality
from agents.scoring_agent import SCORING_VERSION


def kev_at(cache, day):
    endpoint=('https://api.github.com/repos/cisagov/kev-data/commits'
              '?path=known_exploited_vulnerabilities.json&per_page=1&until='+day+'T23:59:59Z')
    index,_=cached_download(cache,'kev-commit-'+day+'.json',[endpoint])
    commits=json.loads(index.read_text())
    if not isinstance(commits,list) or not commits:
        raise RuntimeError('No authoritative KEV commit at '+day)
    sha=commits[0]['sha']
    snapshot,meta=cached_download(cache,'kev-'+day+'.json',[
        f'https://raw.githubusercontent.com/cisagov/kev-data/{sha}/known_exploited_vulnerabilities.json'])
    return {r['cveID'] for r in json.loads(snapshot.read_text())['vulnerabilities']},dict(meta,commit=sha)


def run(cutoff,days,cache):
    cache.mkdir(parents=True,exist_ok=True)
    end=(date.fromisoformat(cutoff)+timedelta(days=days)).isoformat()
    old,old_meta=kev_at(cache,cutoff)
    future,future_meta=kev_at(cache,end)
    epss,epss_meta=cached_download(cache,'epss-'+cutoff+'.csv.gz',[
        f'https://epss.empiricalsecurity.com/epss_scores-{cutoff}.csv.gz',
        f'https://raw.githubusercontent.com/empiricalsec/epss_scores/main/{cutoff[:4]}/epss_scores-{cutoff}.csv.gz'])
    with gzip.open(epss,'rt') as f:
        metadata=f.readline().strip()
        rows=[(r['cve'],float(r['epss'])) for r in csv.DictReader(f) if r['cve'] not in old]
    ranked=sorted(rows,key=lambda r:(-r[1],r[0]))
    available={c for c,_ in ranked}
    labels=(future-old)&available
    metrics={}
    for k in (100,500,1000,5000):
        top={c for c,_ in ranked[:k]}
        hit=len(labels&top)
        metrics[str(k)]={'hits':hit,'top_k_hit_fraction':hit/min(k,len(ranked)) if ranked else None,
                         'recall_of_future_kev_additions':hit/len(labels) if labels else None}
    # In the absence of historical PoC observations, v4 predictive tier is a
    # monotone transform of EPSS. No future PoC/media data is injected.
    v4=sorted(rows,key=lambda r:(-calculate_reality({'epss':r[1]}),r[0]))
    v4_metrics={}
    for k in (100,500,1000,5000):
        hit=len(labels&{c for c,_ in v4[:k]})
        v4_metrics[str(k)]={'hits':hit,'recall_of_future_kev_additions':hit/len(labels) if labels else None}
    return {'algorithm_version':SCORING_VERSION,'cutoff':cutoff,'horizon_days':days,'end':end,'eligible_cves':len(rows),
            'known_kev_excluded':len(old),'new_kev_all':len(future-old),'new_kev_in_cohort':len(labels),
            'epss_metadata':metadata,'snapshots':{'kev_t':old_meta,'kev_end':future_meta,'epss_t':epss_meta},
            'baseline_epss':metrics,'v4_predictive_index':v4_metrics,
            'labels':sorted(labels),
            'limitations':[
                'Target is KEV inclusion, not first exploitation or all exploitation.',
                'Non-KEV CVEs are unlabeled, not confirmed non-exploited negatives.',
                'Historical PoC, media and tone are unavailable and deliberately excluded.',
                'V4 rounds the ordinal index; ties may alter top-K rankings relative to raw EPSS.',
                'A single temporal cohort does not establish calibrated probability or generalization.'
            ]}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--cutoff',default='2026-07-01')
    parser.add_argument('--days',type=int,default=30)
    parser.add_argument('--cohorts',help='Comma-separated historical cutoff dates')
    parser.add_argument('--cache',type=Path,default=Path('data/scoring-lab/cache'))
    parser.add_argument('--report',type=Path,default=Path('data/scoring-lab/backtest.json'))
    args=parser.parse_args()
    result=({'cohorts':[run(c.strip(),args.days,args.cache) for c in args.cohorts.split(',')]}
            if args.cohorts else run(args.cutoff,args.days,args.cache))
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
