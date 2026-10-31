"""El ciclo del worker tiene que ejecutar intel entre enrich y score."""
import agents.alert_agent as alert_agent
import agents.enrichment_agent as enrichment_agent
import agents.intel_agent as intel_agent
import agents.scoring_agent as scoring_agent
import agents.sync_agent as sync_agent
import scripts.run_worker as worker


class _Conn:
    def execute(self, *args, **kwargs):
        return self

    def fetchall(self):
        return []

    def commit(self):
        pass

    def close(self):
        pass


def test_run_cycle_ejecuta_intel_entre_enrich_y_score(monkeypatch):
    orden = []

    monkeypatch.setattr(worker, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(worker, "init_db", lambda *a, **k: None)
    monkeypatch.setattr(worker, "get_db", lambda *a, **k: _Conn())

    # do_sync importa `sync`, no `run`: parchear el nombre equivocado deja
    # correr el clon real de cvelistV5 durante el test.
    monkeypatch.setattr(sync_agent, "sync", lambda *a, **k: orden.append("sync"))
    monkeypatch.setattr(enrichment_agent, "run",
                        lambda *a, **k: orden.append("enrich") or {}, raising=False)
    monkeypatch.setattr(intel_agent, "run_daily",
                        lambda *a, **k: orden.append("intel") or {"skipped": False}, raising=False)
    monkeypatch.setattr(scoring_agent, "run",
                        lambda *a, **k: orden.append("score"), raising=False)
    monkeypatch.setattr(alert_agent, "run",
                        lambda *a, **k: orden.append("alert") or {}, raising=False)

    resumen = worker.run_cycle()

    assert orden == ["sync", "enrich", "intel", "score", "alert"]
    assert resumen["intel"] is not None
