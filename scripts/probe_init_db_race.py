"""Checks that init_db survives simultaneous starts (dashboard+worker) over the same schema."""
import multiprocessing as mp, os, sys, tempfile, pathlib, traceback

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))


def worker(args):
    path, q = args
    try:
        from core.db import init_db
        init_db(path)
        q.put("ok")
    except Exception as e:  # noqa: BLE001
        q.put(f"FAIL {type(e).__name__}: {e}")


if __name__ == "__main__":
    rounds, procs = 6, 4
    bad = 0
    for r in range(rounds):
        path = pathlib.Path(tempfile.gettempdir()) / f"race_{os.getpid()}_{r}.db"
        q = mp.Queue()
        ps = [mp.Process(target=worker, args=((path, q),)) for _ in range(procs)]
        for p in ps:
            p.start()
        res = [q.get() for _ in ps]
        for p in ps:
            p.join()
        fails = [x for x in res if x != "ok"]
        bad += len(fails)
        print(f"round {r}: {len(res)} procesos -> {len(fails)} fallos", fails[:2])
    print("RESULT:", "no races" if bad == 0 else f"{bad} failures")
