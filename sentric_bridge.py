#!/usr/bin/env python3
# sentric_bridge.py - ponte SENTRIC CORE <-> plataforma v5 (FastAPI :8443)
import argparse
import json
import logging
import os
import time
import urllib.request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("bridge")

DATA_DIR = os.path.expanduser("~/sentric-core")
STATE_FILE = os.path.join(DATA_DIR, "sentric_state.json")
TOKEN_FILE = os.path.join(DATA_DIR, "platform_token.txt")
STOP_FILE = os.path.join(DATA_DIR, "STOP_BRIDGE")
DEFAULT_PLATFORM = "http://localhost:8443"

def http(method, url, token=None, payload=None, timeout=10):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:200]
        return e.code, {"error": body}
    except Exception as e:
        return 0, {"error": str(e)}

def load_token():
    token = os.environ.get("SENTRIC_TOKEN", "")
    if not token and os.path.exists(TOKEN_FILE):
        token = open(TOKEN_FILE, encoding="utf-8").read().strip()
    return token

def platform_login(platform):
    code, data = http("POST", platform + "/api/auth/login", payload={})
    if code == 200 and data.get("access_token"):
        log.info("login na plataforma v5 ok (token valido 60 min)")
        return data["access_token"]
    log.warning("login na plataforma falhou: %s %s", code, data)
    return ""

def load_state():
    if not os.path.exists(STATE_FILE):
        return None
    with open(STATE_FILE, encoding="utf-8") as f:
        return json.load(f)

def check_platform(platform):
    code, data = http("GET", platform + "/api/status")
    if code == 200:
        log.info("plataforma v5 ONLINE | %s", json.dumps(data)[:220])
    else:
        log.warning("plataforma v5 respondeu %s: %s", code, data)
    return code == 200

def push_threats(platform, token, state):
    if not token:
        log.warning("sem token da plataforma - pulando push de ameacas")
        return 0
    sent = 0
    for t in state.get("cve_triage", [])[-5:]:
        payload = {
            "source_ip": "0.0.0.0",
            "confidence": 0.95 if t.get("bounty") else 0.6,
            "vector": t["id"] + " | " + t.get("severity", "?") +
                      " | bounty=" + str(t.get("bounty")) +
                      " | " + t.get("reason", "")[:120],
        }
        code, data = http("POST", platform + "/api/threats/report",
                          token=token, payload=payload)
        if code in (200, 201):
            sent += 1
            log.info("ameaca enviada: %s (%s)", t["id"], t.get("severity"))
        else:
            log.warning("falha ao enviar %s: %s %s", t["id"], code, data)
    return sent

def push_survival(state):
    earned = state.get("lifetime_earned", 0.0)
    spent = state.get("lifetime_spent", 0.0)
    score = earned - spent
    log.info("SOBREVIVENCIA: ganho=%.4f gasto=%.4f score=%+.4f | cves=%d oportunidades=%d",
             earned, spent, score,
             state.get("cves_seen", 0),
             len(state.get("opportunities", [])))

def run(platform, interval):
    log.info("ponte SENTRIC core <-> v5 | alvo: %s", platform)
    token = load_token()
    if not token:
        token = platform_login(platform)
    while True:
        if os.path.exists(STOP_FILE):
            log.warning("STOP_BRIDGE detectado - encerrando")
            break
        online = check_platform(platform)
        state = load_state()
        if state:
            push_survival(state)
            if online and token:
                push_threats(platform, token, state)
        else:
            log.warning("state.json do nucleo nao encontrado - rode o sentric_core primeiro")
        time.sleep(interval)

def main():
    ap = argparse.ArgumentParser(description="ponte SENTRIC core -> plataforma v5")
    ap.add_argument("--platform", default=DEFAULT_PLATFORM)
    ap.add_argument("--interval", type=int, default=120)
    ap.add_argument("--once", action="store_true", help="roda uma vez e sai")
    args = ap.parse_args()
    if args.once:
        token = load_token() or platform_login(args.platform)
        check_platform(args.platform)
        state = load_state()
        if state:
            push_survival(state)
            push_threats(args.platform, token, state)
        return
    run(args.platform, args.interval)

if __name__ == "__main__":
    main()
