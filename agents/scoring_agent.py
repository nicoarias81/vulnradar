"""
Scoring Agent — Calcula Hype y Reality para CVEs enriquecidos
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.db import get_db
from core.models import Score
from core.normalizer import build_signals
from core.scoring import score_cve

# Columnas explícitas: cves y enrichments comparten nombres (cve_id, timestamps)
# y un SELECT c.*, e.* devuelve duplicados.
SELECT_ENRICHED = """
    SELECT c.cve_id, c.cvss_score, c.cvss_vector,
           e.in_kev, e.epss, e.wild_confirmation, e.ransomware_use,
           e.media_count, e.poc_count, e.tone_score, e.branding
    FROM cves c
    JOIN enrichments e ON e.cve_id = c.cve_id
    -- Stubs de ensure_cve_stub() sólo tienen cve_id; EPSS masivo no debe puntuarlos.
    WHERE (c.raw_json IS NOT NULL
       OR c.published IS NOT NULL
       OR c.description IS NOT NULL
       OR c.cvss_score IS NOT NULL)
"""

UPSERT_SQL = """
    INSERT INTO scores (cve_id, hype, reality, category)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(cve_id) DO UPDATE SET
        hype = excluded.hype,
        reality = excluded.reality,
        category = excluded.category,
        calculated_at = CURRENT_TIMESTAMP
"""


INSERT_HISTORY_SQL = """
    INSERT INTO score_history (cve_id, hype, reality, category)
    VALUES (?, ?, ?, ?)
"""


def _changed(prev, score) -> bool:
    """True si el score vigente difiere del nuevo.

    Sólo se guarda historial cuando hype o reality se mueven: registrar cada
    recálculo idéntico llenaría la tabla con 398k filas por ciclo.
    """
    if prev is None:
        return True
    return (abs(float(prev[0] or 0) - score.hype) > 1e-9
            or abs(float(prev[1] or 0) - score.reality) > 1e-9)


def _flush_history(conn, rows) -> None:
    if rows:
        conn.executemany(INSERT_HISTORY_SQL, rows)


def score_all(conn) -> int:
    """Un score vigente por CVE (UNIQUE(cve_id)): reemplaza, no acumula filas.

    Los cambios se copian a score_history para poder dibujar la evolución; el
    vigente se lee de una sola pasada en vez de un SELECT por CVE.

    Recorre en orden de cve_id y cometea por tandas: sin el orden, este barrido
    y un backfill puntuando otro lote toman las filas de `scores` en distinto
    orden y Postgres mata a uno por deadlock.
    """
    rows = conn.execute(SELECT_ENRICHED + " ORDER BY c.cve_id").fetchall()
    vigentes = {
        r["cve_id"]: (r["hype"], r["reality"])
        for r in conn.execute("SELECT cve_id, hype, reality FROM scores").fetchall()
    }
    history = []
    for i, row in enumerate(rows, 1):
        # Fila unida: las columnas de cves y de enrichments viven en la misma fila.
        signals = build_signals(row, row)
        score = Score(cve_id=row["cve_id"], **score_cve(signals))
        if _changed(vigentes.get(score.cve_id), score):
            history.append((score.cve_id, score.hype, score.reality, score.category))
        conn.execute(UPSERT_SQL, (score.cve_id, score.hype, score.reality, score.category))
        if i % 2000 == 0:
            _flush_history(conn, history)
            history.clear()
            conn.commit()
    _flush_history(conn, history)
    conn.commit()
    return len(rows)


def score_cves(conn, cve_ids) -> int:
    """Recalcula sólo los CVEs indicados: 398k filas por corrida no es viable."""
    ids = sorted({i for i in (cve_ids or []) if i})
    if not ids:
        return 0
    rows = conn.execute(
        SELECT_ENRICHED + " AND c.cve_id = ANY(?) ORDER BY c.cve_id", (ids,)
    ).fetchall()
    for row in rows:
        signals = build_signals(row, row)
        score = Score(cve_id=row["cve_id"], **score_cve(signals))
        prev = conn.execute(
            "SELECT hype, reality FROM scores WHERE cve_id = ?", (score.cve_id,)
        ).fetchone()
        conn.execute(UPSERT_SQL, (score.cve_id, score.hype, score.reality, score.category))
        if _changed(prev, score):
            conn.execute(
                INSERT_HISTORY_SQL,
                (score.cve_id, score.hype, score.reality, score.category),
            )
    return len(rows)


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
