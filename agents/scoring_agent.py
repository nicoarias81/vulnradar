"""
Scoring Agent — computes Hype and Reality for enriched CVEs
"""
import sys
import json
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.db import get_db
from core.models import Score
from core.normalizer import build_signals
from core.scoring import score_cve, exploitation_state

SCORE_BATCH_SIZE = 2000
# Bump whenever formulas, normalization or category thresholds change.
SCORING_VERSION = "v4.4-poc-score-in-reality"
INPUT_HASH_SQL = f"""md5(jsonb_build_array(
    '{SCORING_VERSION}', c.cvss_score, c.cvss_vector,
    e.in_kev, CASE WHEN left(e.epss_date,10) >= to_char(CURRENT_TIMESTAMP - INTERVAL '7 days','YYYY-MM-DD') AND left(e.epss_date,10) <= to_char(CURRENT_TIMESTAMP,'YYYY-MM-DD') THEN e.epss ELSE NULL END,
    e.wild_confirmation, e.ransomware_use, e.exploitdb_poc_count, e.validated_poc_count, e.poc_count,
    COALESCE(active_media.media_count,0),
    CASE WHEN active_media.media_count>0 THEN e.tone_score ELSE 0 END,
    CASE WHEN active_media.media_count>0 THEN e.branding ELSE 0 END,
    e.epss_date, e.epss_model, e.tone_method, e.tone_model
)::text)"""

SELECT_ENRICHED = f"""
    SELECT c.cve_id, c.cvss_score, c.cvss_vector, c.cvss_source,
           e.in_kev,
           CASE WHEN left(e.epss_date,10) >= to_char(CURRENT_TIMESTAMP - INTERVAL '7 days','YYYY-MM-DD') AND left(e.epss_date,10) <= to_char(CURRENT_TIMESTAMP,'YYYY-MM-DD') THEN e.epss ELSE NULL END AS epss,
           e.epss_date, e.epss_model, e.wild_confirmation, e.ransomware_use,
           e.exploitdb_poc_count, e.validated_poc_count, e.poc_count,
           COALESCE(active_media.media_count,0) AS media_count,
           CASE WHEN active_media.media_count>0 THEN e.tone_score ELSE 0 END AS tone_score,
           CASE WHEN active_media.media_count>0 THEN e.branding ELSE 0 END AS branding,
           e.tone_method, e.tone_model,
           {INPUT_HASH_SQL} AS new_input_hash,
           s.hype AS previous_hype, s.reality AS previous_reality,
           s.category AS previous_category, s.cve_id AS previous_id
    FROM cves c
    JOIN enrichments e ON e.cve_id=c.cve_id
    LEFT JOIN scores s ON s.cve_id=c.cve_id
    LEFT JOIN (
        SELECT cve_id, count(DISTINCT COALESCE(story_key,url)) AS media_count
        FROM media_mentions
        WHERE kind='press' AND published >= to_char(CURRENT_TIMESTAMP-INTERVAL '30 days','YYYY-MM-DD')
          AND left(published,10) <= to_char(CURRENT_TIMESTAMP,'YYYY-MM-DD')
        GROUP BY cve_id
    ) active_media ON active_media.cve_id=c.cve_id
    WHERE c.record_state='PUBLISHED'
      AND (c.raw_json IS NOT NULL OR c.published IS NOT NULL OR c.description IS NOT NULL OR c.cvss_score IS NOT NULL)
      AND (s.input_hash IS DISTINCT FROM {INPUT_HASH_SQL} OR NOT EXISTS (
          SELECT 1 FROM score_evaluations se WHERE se.cve_id=c.cve_id AND se.input_hash={INPUT_HASH_SQL}))
"""

UPSERT_SQL = """
    INSERT INTO scores (cve_id, hype, reality, category, input_hash, exploitation_state, completeness, algorithm_version)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(cve_id) DO UPDATE SET
        hype = excluded.hype,
        reality = excluded.reality,
        category = excluded.category,
        input_hash = excluded.input_hash,
        exploitation_state = excluded.exploitation_state,
        completeness = excluded.completeness,
        algorithm_version = excluded.algorithm_version,
        calculated_at = CURRENT_TIMESTAMP
"""


INSERT_HISTORY_SQL = """
    INSERT INTO score_history (cve_id, hype, reality, category, algorithm_version, input_snapshot, input_hash, exploitation_state)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""


def _changed(prev, score) -> bool:
    """True when the current score differs from the new one.

    History is only written when hype, reality or category change: recording every
    identical recalculation would fill the table with 398k rows per cycle.
    """
    if prev is None:
        return True
    return (abs(float(prev[0] or 0) - score.hype) > 1e-9
            or abs(float(prev[1] or 0) - score.reality) > 1e-9
            or prev[2] != score.category)


def _flush_history(conn, rows) -> None:
    if rows:
        conn.executemany(INSERT_HISTORY_SQL, rows)


def score_all(conn) -> int:
    """Score changed inputs only, with keyset pagination and bounded bulk writes.

    SQL compares versioned input fingerprints; unchanged rows never enter Python.
    A formula version bump invalidates previous fingerprints on the next pass.
    Returns the number of recalculated CVEs.
    """
    last = ""
    count = 0
    while True:
        rows = conn.execute(
            SELECT_ENRICHED + " AND c.cve_id > ? ORDER BY c.cve_id LIMIT ?",
            (last, SCORE_BATCH_SIZE),
        ).fetchall()
        if not rows:
            break
        _score_rows(conn, rows)
        conn.commit()
        count += len(rows)
        last = rows[-1]["cve_id"]
    conn.commit()
    return count


def _score_rows(conn, rows) -> None:
    history, current, evaluations = [], [], []
    for row in rows:
        signals = build_signals(row, row)
        score = Score(cve_id=row["cve_id"], **score_cve(signals))
        previous = None if row["previous_id"] is None else (
            row["previous_hype"], row["previous_reality"], row["previous_category"]
        )
        values = (score.cve_id, score.hype, score.reality, score.category)
        state = exploitation_state(signals)
        completeness = round(1-len(signals.get('missing_fields',[]))/3,3)
        current.append((*values, row["new_input_hash"], state, completeness, SCORING_VERSION))
        snapshot = {'signals':signals,'epss_date':row['epss_date'],'epss_model':row['epss_model'],
                        'cvss_source':row['cvss_source'],'tone_method':row['tone_method'], 'tone_model':row['tone_model']}
        evaluations.append((score.cve_id,row['new_input_hash'],SCORING_VERSION,json.dumps(snapshot,default=str),score.hype,score.reality,score.category))
        if _changed(previous, score):
            history.append((*values, SCORING_VERSION, json.dumps(snapshot,default=str), row['new_input_hash'], state))
    if current:
        conn.executemany(UPSERT_SQL, current)
        conn.executemany('''INSERT INTO score_evaluations(cve_id,input_hash,algorithm_version,input_snapshot,hype,reality,category)
            VALUES (?,?,?,?,?,?,?) ON CONFLICT(cve_id,input_hash) DO NOTHING''', evaluations)
    _flush_history(conn, history)


def score_cves(conn, cve_ids) -> int:
    """Recomputes only the given CVEs: 398k rows per run is not viable."""
    ids = sorted({i for i in (cve_ids or []) if i})
    if not ids:
        return 0
    count = 0
    for start in range(0, len(ids), SCORE_BATCH_SIZE):
        rows = conn.execute(
            SELECT_ENRICHED + " AND c.cve_id = ANY(?) ORDER BY c.cve_id",
            (ids[start:start + SCORE_BATCH_SIZE],),
        ).fetchall()
        _score_rows(conn, rows)
        count += len(rows)
    return count


def run(db_path=None):
    from core.db import init_db

    path = init_db(db_path)
    conn = get_db(path)
    try:
        count = score_all(conn)
        conn.commit()
    finally:
        conn.close()
    print(f"Scoring completado: {count} CVEs.")


if __name__ == "__main__":
    run()
