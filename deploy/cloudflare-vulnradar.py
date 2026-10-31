#!/usr/bin/env python3
"""Ingress del túnel + DNS para vulnradar.munalabs.eu (sitio PÚBLICO, sin Access).

Corre EN el server, con las credenciales de /opt/cloudflare/credentials.env:

    ssh ... 'set -a; source /opt/cloudflare/credentials.env; set +a; python3 -' < deploy/cloudflare-vulnradar.py

Idempotente: si el hostname ya está en el ingress o el registro DNS ya existe, no lo duplica.
Sólo imprime etiquetas/estado, nunca tokens.
"""
import json
import os
import sys
import urllib.error
import urllib.request

HOST = "vulnradar.munalabs.eu"
SERVICE = "http://localhost:8501"

TOKEN = os.environ["CLOUDFLARE_API_TOKEN"]
ACCOUNT = os.environ["CLOUDFLARE_ACCOUNT_ID"]
ZONE = os.environ["CLOUDFLARE_ZONE_ID_MUNALABS"]
TUNNEL = os.environ["CLOUDFLARE_TUNNEL_ID"]
API = "https://api.cloudflare.com/client/v4"
DRY = "--dry-run" in sys.argv


def call(method: str, path: str, body: dict | None = None) -> dict:
    if DRY and method != "GET":
        print(f"dry-run: {method} {path} (no se envía)")
        return {}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("Authorization", f"Bearer {TOKEN}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as exc:
        payload = json.loads(exc.read().decode() or "{}")
        payload.setdefault("success", False)
    if not payload.get("success"):
        raise SystemExit(f"error {method} {path}: {payload.get('errors')}")
    return payload["result"]


def ingress() -> None:
    path = f"/accounts/{ACCOUNT}/cfd_tunnel/{TUNNEL}/configurations"
    cfg = call("GET", path)["config"]
    rules = cfg.get("ingress") or []

    if any(r.get("hostname") == HOST for r in rules):
        print(f"ingress: {HOST} ya presente")
    else:
        new = {"hostname": HOST, "service": SERVICE}
        # El catch-all (regla sin hostname) tiene que quedar último.
        idx = next((i for i, r in enumerate(rules) if not r.get("hostname")), len(rules))
        rules.insert(idx, new)
        cfg["ingress"] = rules
        call("PUT", path, {"config": cfg})
        verb = "se agregaría" if DRY else "agregado"
        print(f"ingress: {HOST} -> {SERVICE} {verb} (catch-all al final)")

    rules = call("GET", path)["config"]["ingress"]
    order = [r.get("hostname") or "*catch-all*" for r in rules]
    print("ingress final:", " | ".join(order))


def dns() -> None:
    found = call("GET", f"/zones/{ZONE}/dns_records?name={HOST}")
    target = f"{TUNNEL}.cfargotunnel.com"
    if found:
        rec = found[0]
        ok = rec["type"] == "CNAME" and rec["content"] == target and rec.get("proxied")
        print(f"dns: existe {rec['type']} proxy={rec.get('proxied')} ok={ok}")
        if not ok:
            print("dns: ATENCIÓN, el registro existente no es el CNAME proxied esperado; no se modifica")
        return
    call("POST", f"/zones/{ZONE}/dns_records", {
        "type": "CNAME",
        "name": HOST,
        "content": target,
        "proxied": True,
        "ttl": 1,
        "comment": "vulnradar (cloudflare tunnel)",
    })
    print(f"dns: CNAME {HOST} -> {target} proxied {'se crearía' if DRY else 'creado'}")


def access() -> None:
    apps = call("GET", f"/accounts/{ACCOUNT}/access/apps?name={HOST}")
    hits = [a["name"] for a in apps if HOST in (a.get("domain") or "")]
    if hits:
        print(f"access: ATENCIÓN hay app(s) que cubren el dominio: {hits} (sitio público: borrar si bloquea)")
    else:
        print("access: sin apps (correcto para sitio público)")


if __name__ == "__main__":
    ingress()
    dns()
    access()
