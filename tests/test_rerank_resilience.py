"""Resilience of the feed rerank and the dates it stores.

Two regressions live here: a dead LLM that keeps burning 60 s per remaining
batch, and RFC 822 dates landing in a column that every window compares as text.
"""
import time

from agents import enrichment_agent as agent


def test_gives_up_after_two_consecutive_failed_batches():
    entries = [{"title": f"Titulo {i}"} for i in range(20)]
    calls = []

    def boom(prompt):
        calls.append(prompt)
        raise RuntimeError("litellm timeout")

    out = agent.rerank_entries(entries, completer=boom, batch_size=2)

    # 20 entries / 2 per batch = 10 batches, but the second failure stops the cycle.
    assert len(calls) == agent.RERANK_MAX_FAILURES
    assert out == [{} for _ in entries]


def test_recovers_after_a_single_failure():
    entries = [{"title": f"CVE-2026-1111 caso {i}"} for i in range(4)]
    calls = []

    def flaky(prompt):
        calls.append(prompt)
        if len(calls) == 1:
            raise RuntimeError("first batch dies")
        return '[{"i": 1, "cve_id": "CVE-2026-1111", "relevant": true}]'

    out = agent.rerank_entries(entries, completer=flaky, batch_size=2)

    assert len(calls) == 2          # one failure does not end the run
    assert out[2]["cve_id"] == "CVE-2026-1111"


def test_mentions_from_rerank_stores_iso_dates():
    stamp = time.struct_time((2026, 9, 30, 7, 0, 0, 2, 273, 0))
    entries = [{
        "title": "Chrome RCE",
        "url": "https://x/1",
        "source": "x",
        "published": "Wed, 30 Sep 2026 07:00:00 GMT",
        "published_parsed": stamp,
    }]
    reranked = [{"cve_id": "CVE-2026-3333", "relevant": True}]

    mentions = agent.mentions_from_rerank(entries, reranked)

    # An RFC 822 string sorts after every ISO date and defeats the 30 day window.
    assert mentions[0]["published"] == "2026-09-30T07:00:00Z"
