"""
Alert Agent — flags when a CVE deserves attention.

Reads the current scores (JOIN cves + enrichments), evaluates opt-in rules and
delivers over Slack and/or a generic webhook. The `alerts_sent` table is the
anti-spam lock: an alert already sent is never repeated.

Usage:
    python agents/alert_agent.py                 # one pass and exit (default)
    python agents/alert_agent.py --dry-run       # evaluate and print, no POST and no writes
    python agents/alert_agent.py --skip-slack    # generic webhook only
    python agents/alert_agent.py --once

Rules (all opt-in by threshold, there are no "default" alerts):
    overhyped        category == "Overhyped"      high hype, low fear
    earned_the_hype  category == "Earned the hype" high hype and fear
    humo             tone_score >= 7 and reality < 5  media hype
    sleeper          category == "Sleeper"        high fear, little press

A CVE can trip more than one rule: each (cve_id, rule) pair is a separate alert
and is deduplicated by its own row in `alerts_sent`.

Channels (URLs from the environment; a channel with no URL is skipped):
    SLACK_WEBHOOK_URL   Slack incoming webhook      -> JSON {text, blocks}
    ALERT_WEBHOOK_URL   generic webhook (JSON POST)

Tests have no network: `session` is injectable (anything with `.post` will do).
"""
import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.db import get_db, init_db
from core.labels import category_display

USER_AGENT = "vulnradar/0.4 (+https://github.com/nicoarias81/vulnradar)"
TIMEOUT_SECONDS = 15

NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"

# Threshold for the "humo" rule: panic in the headlines with no real fear behind.
HUMO_TONE_THRESHOLD = 7.0
HUMO_REALITY_THRESHOLD = 5.0

SLACK_ENV = "SLACK_WEBHOOK_URL"
WEBHOOK_ENV = "ALERT_WEBHOOK_URL"

RULE_LABELS = {
    'watch': 'Public PoC / high exploitation prediction',
    "confirmed_exploitation": "Confirmed exploitation",
    "overhyped": "High attention + lower observed evidence",
    "earned_the_hype": "High attention + observed exploitation",
    "humo": "Strong headline tone + lower threat index",
    "sleeper": "Observed exploitation + lower recent attention",
}

# scores has UNIQUE(cve_id): no MAX(id) or history window needed, the CVE row
# already IS the current score. enrichments may be missing (LEFT JOIN).
SELECT_SCORED = """
    SELECT s.cve_id, s.hype, s.reality, s.category, s.calculated_at,
           c.description, c.cvss_score, c.cvss_severity,
           e.tone_score, e.media_count, e.in_kev, e.epss, e.poc_count,
           e.branding, e.brand_name, e.wild_confirmation, s.exploitation_state
    FROM scores s
    JOIN cves c ON c.cve_id = s.cve_id
    LEFT JOIN enrichments e ON e.cve_id = s.cve_id
    ORDER BY s.reality DESC, s.hype DESC, s.cve_id
"""

INSERT_SENT = """
    INSERT INTO alerts_sent (cve_id, channel, rule, payload_hash)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(cve_id, channel, rule) DO NOTHING
"""


@dataclass
class Alert:
    """One rule fired on one CVE: the unit that travels and gets deduplicated."""

    cve_id: str
    rule: str
    category: str
    hype: float
    reality: float
    tone_score: float | None = None
    media_count: int = 0
    in_kev: bool = False
    epss: float | None = None
    poc_count: int = 0
    branding: bool = False
    brand_name: str | None = None
    description: str | None = None

    @property
    def label(self) -> str:
        return RULE_LABELS.get(self.rule, self.rule)

    @property
    def url(self) -> str:
        return NVD_URL.format(cve_id=self.cve_id)


# --------------------------------------------------------------------------
# Reading current scores and evaluating rules
# --------------------------------------------------------------------------
def load_scored(conn) -> list:
    """Current scores with their CVE and, when present, their enrichment."""
    return conn.execute(SELECT_SCORED).fetchall()


def fired_rules(row, *, humo_tone=HUMO_TONE_THRESHOLD,
                humo_reality=HUMO_REALITY_THRESHOLD) -> list:
    """Rules a row fires, in stable order. No signals, no rule."""
    category = (row["category"] or "").strip()
    rules = []
    confirmed = bool(row.get('in_kev') or row.get('wild_confirmation'))
    if confirmed:
        rules.append('confirmed_exploitation')
    if category == "Overhyped" and not confirmed:
        rules.append("overhyped")
    if category == "Earned the hype":
        rules.append("earned_the_hype")

    tone = row["tone_score"]
    reality = row["reality"]
    # "humo": panic headlines with little real fear. Independent of the category.
    if not confirmed and category not in ('Unknown','Watch') and tone is not None and reality is not None \
            and tone >= humo_tone and reality < humo_reality:
        rules.append("humo")

    if category == "Sleeper":
        rules.append("sleeper")
    if category == 'Watch':
        rules.append('watch')
    return rules


def build_alerts(rows, *, humo_tone=HUMO_TONE_THRESHOLD,
                 humo_reality=HUMO_REALITY_THRESHOLD) -> list:
    """One Alert per fired rule. The category comes from the score, it is not recomputed."""
    alerts = []
    for row in rows:
        for rule in fired_rules(row, humo_tone=humo_tone, humo_reality=humo_reality):
            alerts.append(Alert(
                cve_id=row["cve_id"],
                rule=rule,
                category=row["category"] or "",
                hype=_num(row["hype"]),
                reality=_num(row["reality"]),
                tone_score=row["tone_score"],
                media_count=row["media_count"] or 0,
                in_kev=bool(row["in_kev"]),
                epss=row["epss"],
                poc_count=row["poc_count"] or 0,
                branding=bool(row["branding"]),
                brand_name=row["brand_name"],
                description=row["description"],
            ))
    return alerts


def evaluate(conn, *, humo_tone=HUMO_TONE_THRESHOLD,
             humo_reality=HUMO_REALITY_THRESHOLD) -> list:
    """Sugar over build_alerts for callers that already hold the connection."""
    return build_alerts(load_scored(conn), humo_tone=humo_tone,
                        humo_reality=humo_reality)


# --------------------------------------------------------------------------
# Payloads
# --------------------------------------------------------------------------
def build_slack_payload(alert: Alert) -> dict:
    """Slack incoming webhook: `text` always present, `blocks` kept simple."""
    summary = (f"{alert.cve_id} — {alert.label} "
               f"(hype {alert.hype:.1f} / reality {alert.reality:.1f})")
    return {
        "text": summary,
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{alert.cve_id} · {alert.label}"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": _details_text(alert)},
            },
        ],
    }


def build_webhook_payload(alert: Alert) -> dict:
    """Generic webhook: plain JSON for any consumer."""
    return {
        "event": "vulnradar.alert",
        "cve_id": alert.cve_id,
        "rule": alert.rule,
        "category": alert.category,
        "category_label": category_display(alert.category),
        "hype": alert.hype,
        "reality": alert.reality,
        "description": alert.description,
        "url": alert.url,
        "signals": {
            "tone_score": alert.tone_score,
            "media_count": alert.media_count,
            "in_kev": alert.in_kev,
            "epss": alert.epss,
            "poc_count": alert.poc_count,
            "branding": alert.branding,
            "brand_name": alert.brand_name,
        },
    }


def build_payload(alert: Alert, channel: str) -> dict:
    return build_slack_payload(alert) if channel == "slack" else build_webhook_payload(alert)


def payload_hash(payload: dict) -> str:
    """sha256 of the canonical JSON: an audit trail of what was really sent."""
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Delivery and dedupe
# --------------------------------------------------------------------------
def already_sent(conn, alert: Alert, channel: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM alerts_sent WHERE cve_id = ? AND channel = ? AND rule = ?",
        (alert.cve_id, channel, alert.rule),
    ).fetchone()
    return row is not None


def post_alert(session, url, payload, *, channel, cve_id) -> bool:
    """POST with a timeout. A 4xx/5xx or an exception returns False: it is not marked."""
    headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    try:
        response = session.post(url, json=payload, headers=headers,
                                timeout=TIMEOUT_SECONDS)
    except Exception as exc:  # timeout, DNS, TLS, connection refused
        print(f"{channel} {cve_id}: {exc}")
        return False

    status = getattr(response, "status_code", 0)
    if status >= 400 or status == 0:
        print(f"{channel} {cve_id}: HTTP {status}. Not marked as sent.")
        return False
    return True


def mark_sent(conn, alert: Alert, channel: str, digest: str) -> None:
    """Only called after a successful POST."""
    conn.execute(INSERT_SENT, (alert.cve_id, channel, alert.rule, digest))


def resolve_channel_url(env, name, explicit=None) -> str | None:
    """Channel URL: the explicit argument overrides the environment. No URL, no channel."""
    value = explicit if explicit is not None else env.get(name)
    value = (value or "").strip()
    return value or None


# --------------------------------------------------------------------------
# Orchestration and CLI
# --------------------------------------------------------------------------
def run(*, dry_run=False, skip_slack=False, skip_webhook=False, db_path=None,
        session=None, env=None, slack_url=None, webhook_url=None,
        humo_tone=HUMO_TONE_THRESHOLD, humo_reality=HUMO_REALITY_THRESHOLD) -> dict:
    """
    One pass: evaluate, drop what was already sent, deliver on active channels.

    `dry_run` neither POSTs nor writes to alerts_sent: it only prints the plan.
    """
    environ = os.environ if env is None else env
    http = session or requests

    channels = []
    if not skip_slack:
        url = resolve_channel_url(environ, SLACK_ENV, slack_url)
        if url:
            channels.append(("slack", url))
    if not skip_webhook:
        url = resolve_channel_url(environ, WEBHOOK_ENV, webhook_url)
        if url:
            channels.append(("webhook", url))

    path = init_db(db_path)  # idempotent: creates alerts_sent when missing
    conn = get_db(path)
    summary = {"evaluated": 0, "alerts": 0, "pending": 0, "sent": 0,
               "skipped": 0, "failed": 0, "channels": [name for name, _ in channels]}
    try:
        rows = load_scored(conn)
        alerts = build_alerts(rows, humo_tone=humo_tone, humo_reality=humo_reality)
        summary["evaluated"] = len(rows)
        summary["alerts"] = len(alerts)

        if not channels:
            print("No channels configured: set SLACK_WEBHOOK_URL or ALERT_WEBHOOK_URL.")

        for alert in alerts:
            for channel, url in channels:
                payload = build_payload(alert, channel)
                if already_sent(conn, alert, channel):
                    summary["skipped"] += 1
                    continue
                summary["pending"] += 1

                if dry_run:
                    print(f"[dry-run] {channel}: {alert.cve_id} {alert.rule} "
                          f"(hype {alert.hype:.1f} / reality {alert.reality:.1f})")
                    continue

                if post_alert(http, url, payload, channel=channel, cve_id=alert.cve_id):
                    mark_sent(conn, alert, channel, payload_hash(payload))
                    conn.commit()
                    summary["sent"] += 1
                else:
                    summary["failed"] += 1
    finally:
        conn.close()

    if not summary["alerts"]:
        print("Nothing to alert: no scores trigger any rules.")
    elif dry_run:
        print(f"[dry-run] {summary['pending']} alerts pending, "
              f"{summary['skipped']} already sent. Nothing was sent and nothing was written.")
    else:
        print(f"Alerts: evaluated={summary['evaluated']} triggered={summary['alerts']} "
              f"sent={summary['sent']} skipped={summary['skipped']} "
              f"failed={summary['failed']} channels={','.join(summary['channels']) or 'none'}")
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CVE alerts via Slack and/or a generic webhook (dedupe in alerts_sent).",
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Evaluates and prints. Does not POST or write to alerts_sent.")
    parser.add_argument("--once", action="store_true",
                        help="A single pass, then exits (default behavior).")
    parser.add_argument("--skip-slack", action="store_true", help="No usa SLACK_WEBHOOK_URL.")
    parser.add_argument("--skip-webhook", action="store_true", help="No usa ALERT_WEBHOOK_URL.")
    parser.add_argument("--humo-tone", type=float, default=HUMO_TONE_THRESHOLD,
                        help=f"minimum tone_score for the humo rule (default {HUMO_TONE_THRESHOLD}).")
    parser.add_argument("--humo-reality", type=float, default=HUMO_REALITY_THRESHOLD,
                        help=f"maximum reality for the humo rule (default {HUMO_REALITY_THRESHOLD}).")
    parser.add_argument("--db-path", default=None, help="Test schema. Production: DATABASE_URL.")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    summary = run(
        dry_run=args.dry_run,
        skip_slack=args.skip_slack,
        skip_webhook=args.skip_webhook,
        db_path=args.db_path,
        humo_tone=args.humo_tone,
        humo_reality=args.humo_reality,
    )
    # A dead channel does not break the run, but it shows up in the exit code.
    return 1 if summary["failed"] else 0


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _details_text(alert: Alert) -> str:
    lines = [f"*Hype* {alert.hype:.1f} · *Reality* {alert.reality:.1f} · "
             f"*{category_display(alert.category)}*"]
    if alert.description:
        lines.append(alert.description.strip()[:400])
    senales = []
    if alert.in_kev:
        senales.append("KEV")
    if alert.tone_score is not None:
        senales.append(f"tone {alert.tone_score:g}")
    senales.append(f"media {alert.media_count}")
    senales.append(f"PoCs {alert.poc_count}")
    lines.append(" · ".join(senales))
    lines.append(alert.url)
    return "\n".join(lines)


def _num(value) -> float:
    try:
        return round(float(value), 2)
    except (TypeError, ValueError):
        return 0.0


if __name__ == "__main__":
    raise SystemExit(main())
