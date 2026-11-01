"""Benchmark full real-data scoring into session-local temporary output tables."""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.db import get_db
from agents.scoring_agent import score_all, SCORING_VERSION


def main():
    if os.getenv('VULNRADAR_LAB')!='1':
        raise RuntimeError('Benchmark requires the isolated lab')
    conn=get_db()
    try:
        if conn.execute('SELECT current_database()').fetchone()[0]!='radar_lab':
            raise RuntimeError('Refusing other databases')
        for table in ('scores','score_history','score_evaluations'):
            conn.execute(f'CREATE TEMP TABLE {table} (LIKE public.{table} INCLUDING ALL)')
        conn.commit()
        started=time.monotonic()
        rows=score_all(conn)
        elapsed=time.monotonic()-started
        started=time.monotonic()
        repeated=score_all(conn)
        second=time.monotonic()-started
        import resource
        result={'algorithm_version':SCORING_VERSION,'real_cves_scored':rows,
                'full_seconds':round(elapsed,3),'rows_per_second':round(rows/elapsed,1),
                'unchanged_recalculated':repeated,'unchanged_seconds':round(second,3),
                'peak_rss_mib':round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,1),
                'scope':'Session-local temporary output tables; persistent scores and observations remain untouched.'}
        path=Path('/lab/benchmark.json')
        path.write_text(json.dumps(result,indent=2),encoding='utf-8')
        print(json.dumps(result,indent=2),flush=True)
        return 0 if rows>=100000 and repeated==0 else 1
    finally:
        conn.close()


if __name__=='__main__':
    raise SystemExit(main())
