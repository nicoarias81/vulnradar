"""
Alert Agent — avisa cuando un CVE merece atención.

Lee los scores vigentes (JOIN cves + enrichments), evalúa reglas opt-in y
entrega por Slack y/o webhook genérico. La tabla `alerts_sent` es el candado
anti-spam: una alerta enviada no se repite.

Uso:
    python agents/alert_agent.py                 # una pasada y sale (default)
    python agents/alert_agent.py --dry-run       # evalúa e imprime, sin POST ni escrituras
    python agents/alert_agent.py --skip-slack    # sólo webhook genérico
    python agents/alert_agent.py --once

Reglas (todas opt-in por umbral, no hay alertas "por defecto"):
    overhyped        category == "Overhyped"      hype alto, miedo bajo
    earned_the_hype  category == "Earned the hype" hype y miedo altos
    humo             tone_score >= 7 y reality < 5  humo mediático
    sleeper          category == "Sleeper"        miedo alto, poca prensa

Un CVE puede disparar más de una regla: cada (cve_id, regla) es una alerta
distinta y se deduplica por su propia fila en `alerts_sent`.

Canales (URLs por entorno; sin URL el canal se omite):
    SLACK_WEBHOOK_URL   Slack incoming webhook      -> JSON {text, blocks}
    ALERT_WEBHOOK_URL   webhook genérico (JSON POST)

En tests no hay red: `session` es inyectable (basta un objeto con `.post`).
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

USER_AGENT = "vulnradar/0.4 (+https://github.com/nicoarias81/vulnradar)"
TIMEOUT_SECONDS = 15

NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"

# Umbral de la regla "humo": pánico en los titulares sin miedo real detrás.
HUMO_TONE_THRESHOLD = 7.0
HUMO_REALITY_THRESHOLD = 5.0

SLACK_ENV = "SLACK_WEBHOOK_URL"
WEBHOOK_ENV = "ALERT_WEBHOOK_URL"

RULE_LABELS = {
    "overhyped": "Overhyped",
    "earned_the_hype": "Earned the hype",
    "humo": "Hype sin sustento",
    "sleeper": "Sleeper",
}

# scores tiene UNIQUE(cve_id): no hace falta MAX(id) ni ventana histórica,
# la fila del CVE ya ES el score vigente. enrichments puede faltar (LEFT JOIN).
SELECT_SCORED = """
    SELECT s.cve_id, s.hype, s.reality, s.category, s.calculated_at,
           c.description, c.cvss_score, c.cvss_severity,
           e.tone_score, e.media_count, e.in_kev, e.epss, e.poc_count,
           e.branding, e.brand_name
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
    """Una regla disparada sobre un CVE: la unidad que viaja y se deduplica."""

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
# Lectura de scores vigentes y evaluación de reglas
# --------------------------------------------------------------------------
def load_scored(conn) -> list:
    """Scores vigentes con su CVE y (si existe) su enrichment."""
    return conn.execute(SELECT_SCORED).fetchall()


def fired_rules(row, *, humo_tone=HUMO_TONE_THRESHOLD,
                humo_reality=HUMO_REALITY_THRESHOLD) -> list:
    """Reglas que dispara una fila, en orden estable. Sin señales, no hay regla."""
    category = (row["category"] or "").strip()
    rules = []
    if category == "Overhyped":
        rules.append("overhyped")
    if category == "Earned the hype":
        rules.append("earned_the_hype")

    tone = row["tone_score"]
    reality = row["reality"]
    # "humo": titulares de pánico con poco miedo real. Independiente de la categoría.
    if tone is not None and reality is not None \
            and tone >= humo_tone and reality < humo_reality:
        rules.append("humo")

    if category == "Sleeper":
        rules.append("sleeper")
    return rules


def build_alerts(rows, *, humo_tone=HUMO_TONE_THRESHOLD,
                 humo_reality=HUMO_REALITY_THRESHOLD) -> list:
    """Una Alert por cada regla disparada. La categoría sale del score, no se recalcula."""
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
    """Azúcar sobre build_alerts para quien ya tiene la conexión."""
    return build_alerts(load_scored(conn), humo_tone=humo_tone,
                        humo_reality=humo_reality)


# --------------------------------------------------------------------------
# Payloads
# --------------------------------------------------------------------------
def build_slack_payload(alert: Alert) -> dict:
    """Slack incoming webhook: `text` siempre presente, `blocks` simple."""
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
    """Webhook genérico: JSON plano para cualquier consumidor."""
    return {
        "event": "vulnradar.alert",
        "cve_id": alert.cve_id,
        "rule": alert.rule,
        "category": alert.category,
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
    """sha256 del JSON canónico: auditoría de qué se envió realmente."""
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Envío y dedupe
# --------------------------------------------------------------------------
def already_sent(conn, alert: Alert, channel: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM alerts_sent WHERE cve_id = ? AND channel = ? AND rule = ?",
        (alert.cve_id, channel, alert.rule),
    ).fetchone()
    return row is not None


def post_alert(session, url, payload, *, channel, cve_id) -> bool:
    """POST con timeout. Un 4xx/5xx o una excepción devuelven False: no se marca."""
    headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    try:
        response = session.post(url, json=payload, headers=headers,
                                timeout=TIMEOUT_SECONDS)
    except Exception as exc:  # timeout, DNS, TLS, conexión rechazada
        print(f"{channel} {cve_id}: {exc}")
        return False

    status = getattr(response, "status_code", 0)
    if status >= 400 or status == 0:
        print(f"{channel} {cve_id}: HTTP {status}. Not marked as sent.")
        return False
    return True


def mark_sent(conn, alert: Alert, channel: str, digest: str) -> None:
    """Sólo se llama después de un POST exitoso."""
    conn.execute(INSERT_SENT, (alert.cve_id, channel, alert.rule, digest))


def resolve_channel_url(env, name, explicit=None) -> str | None:
    """URL del canal: el argumento explícito pisa el entorno. Sin URL, no hay canal."""
    value = explicit if explicit is not None else env.get(name)
    value = (value or "").strip()
    return value or None


# --------------------------------------------------------------------------
# Orquestación y CLI
# --------------------------------------------------------------------------
def run(*, dry_run=False, skip_slack=False, skip_webhook=False, db_path=None,
        session=None, env=None, slack_url=None, webhook_url=None,
        humo_tone=HUMO_TONE_THRESHOLD, humo_reality=HUMO_REALITY_THRESHOLD) -> dict:
    """
    Una pasada: evalúa, filtra lo ya enviado y entrega por los canales activos.

    `dry_run` no POSTea ni escribe en alerts_sent: sólo imprime el plan.
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

    path = init_db(db_path)  # idempotente: crea alerts_sent si falta
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
        print("Nada para alertar: no hay scores que disparen reglas.")
    elif dry_run:
        print(f"[dry-run] {summary['pending']} alertas pendientes, "
              f"{summary['skipped']} ya enviadas. No se envió ni se escribió nada.")
    else:
        print(f"Alertas: evaluadas={summary['evaluated']} disparadas={summary['alerts']} "
              f"enviadas={summary['sent']} omitidas={summary['skipped']} "
              f"fallidas={summary['failed']} canales={','.join(summary['channels']) or 'ninguno'}")
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Alertas de CVEs por Slack y/o webhook genérico (dedupe en alerts_sent).",
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Evalúa e imprime. No POSTea ni escribe alerts_sent.")
    parser.add_argument("--once", action="store_true",
                        help="Una sola pasada y sale (comportamiento por defecto).")
    parser.add_argument("--skip-slack", action="store_true", help="No usa SLACK_WEBHOOK_URL.")
    parser.add_argument("--skip-webhook", action="store_true", help="No usa ALERT_WEBHOOK_URL.")
    parser.add_argument("--humo-tone", type=float, default=HUMO_TONE_THRESHOLD,
                        help=f"tone_score mínimo para la regla humo (default {HUMO_TONE_THRESHOLD}).")
    parser.add_argument("--humo-reality", type=float, default=HUMO_REALITY_THRESHOLD,
                        help=f"reality máximo para la regla humo (default {HUMO_REALITY_THRESHOLD}).")
    parser.add_argument("--db-path", default=None, help="Schema de test. Producción: DATABASE_URL.")
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
    # Un canal caído no rompe la corrida, pero se refleja en el exit code.
    return 1 if summary["failed"] else 0


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _details_text(alert: Alert) -> str:
    lines = [f"*Hype* {alert.hype:.1f} · *Reality* {alert.reality:.1f} · "
             f"*{alert.category or 'sin categoría'}*"]
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
