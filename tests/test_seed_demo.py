"""El seed de demo cubre las 4 categorías y es idempotente."""
from scripts.seed_demo import DEMOS, seed
from core.db import get_db, init_db


def test_seed_demo_cubre_las_cuatro_categorias(tmp_path):
    path = tmp_path / "demo.db"
    init_db(path)
    assert seed(path) == len(DEMOS)

    conn = get_db(path)
    try:
        cats = {row[0] for row in conn.execute("SELECT DISTINCT category FROM scores")}
        n = conn.execute("SELECT COUNT(*) FROM scores").fetchone()[0]
        alertados = conn.execute("SELECT COUNT(*) FROM alerts_sent").fetchone()[0]
    finally:
        conn.close()

    assert n == len(DEMOS)
    assert cats == {"Overhyped", "Earned the hype", "Sleeper", "Quiet"}
    assert alertados >= 1

    assert seed(path) == len(DEMOS)
    conn = get_db(path)
    try:
        n2 = conn.execute("SELECT COUNT(*) FROM scores").fetchone()[0]
    finally:
        conn.close()
    assert n2 == len(DEMOS)
