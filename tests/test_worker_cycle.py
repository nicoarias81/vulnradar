"""The worker cycle must run intel between enrich and score."""
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


def test_run_cycle_runs_intel_between_enrich_and_score(monkeypatch):
    order = []

    monkeypatch.setattr(worker, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(worker, "init_db", lambda *a, **k: None)
    monkeypatch.setattr(worker, "get_db", lambda *a, **k: _Conn())

    # do_sync imports `sync`, not `run`: patching the wrong name lets
    # the real cvelistV5 clone run during the test.
    monkeypatch.setattr(sync_agent, "sync", lambda *a, **k: order.append("sync"))
    monkeypatch.setattr(enrichment_agent, "run",
                        lambda *a, **k: order.append("enrich") or {}, raising=False)
    monkeypatch.setattr(intel_agent, "run_daily",
                        lambda *a, **k: order.append("intel") or {"skipped": False}, raising=False)
    monkeypatch.setattr(scoring_agent, "run",
                        lambda *a, **k: order.append("score"), raising=False)
    monkeypatch.setattr(alert_agent, "run",
                        lambda *a, **k: order.append("alert") or {}, raising=False)

    summary = worker.run_cycle()

    assert order == ["sync", "enrich", "intel", "score", "alert"]
    assert summary["intel"] is not None
