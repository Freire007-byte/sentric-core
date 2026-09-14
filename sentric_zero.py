#!/usr/bin/env python3
# sentric_zero.py - SENTRIC v0.5 - Inteligencia zero-day (recon + scoring)
import argparse
import json
import logging
import os
import re
import sys
import time
import urllib.request
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("zero")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

DATA_DIR = os.path.expanduser("~/sentric-core")
CORE_STATE = os.path.join(DATA_DIR, "sentric_state.json")
ZERO_STATE = os.path.join(DATA_DIR, "zero_state.json")
STOP_FILE = os.path.join(DATA_DIR, "STOP_ZERO")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_SEARCH = "https://api.github.com/search/repositories"

# vendors tutorial/projeto academico: CVE existe mas ninguem paga bounty
JUNK_VENDORS = ("code-projects", "mstfakts", "mstafaks", "hotel and tourism",
                "college-management", "sourcecodester")

# produtos que conseguimos reproduzir em laboratorio local (fase v0.6)
LAB_REGISTRY = {
    "apache": "httpd",
    "nginx": "nginx",
    "openssh": "openssh",
    "wordpress": "wordpress",
    "mysql": "mysql",
    "redis": "redis",
    "postgresql": "postgres",
    "tomcat": "tomcat",
    "node.js": "node",
    "gitlab": "gitlab",
    "jenkins": "jenkins",
    "grafana": "grafana",
    "misp": "misp",
}

def http_get_json(url, headers=None):
    h = {"User-Agent": "Mozilla/5.0"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())

def load_core_state():
    if not os.path.exists(CORE_STATE):
        return None
    with open(CORE_STATE, encoding="utf-8") as f:
        return json.load(f)

def load_zero_state():
    if os.path.exists(ZERO_STATE):
        with open(ZERO_STATE, encoding="utf-8") as f:
            return json.load(f)
    return {"processed": [], "opportunities": []}

def save_zero_state(state):
    tmp = ZERO_STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, ZERO_STATE)

def enrich_cve(cid):
    try:
        data = http_get_json(NVD_URL + "?cveId=" + cid)
    except Exception as e:
        log.warning("NVD detail falhou %s: %s", cid, e)
        return None
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})
    product = None
    version = None
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                crit = m.get("criteria", "")
                parts = crit.split(":")
                if len(parts) >= 6 and parts[2] in ("a", "o"):
                    product = parts[4]
                    version = parts[5]
                    break
            if product:
                break
        if product:
            break
    refs = [r.get("url", "") for r in cve.get("references", [])][:8]
    return {"product": product, "version": version, "refs": refs}

def check_public_poc(cid):
    try:
        data = http_get_json(GITHUB_SEARCH + "?q=" + cid + "&per_page=1")
        total = data.get("total_count", 0)
        return total
    except Exception as e:
        log.warning("github search falhou %s: %s", cid, e)
        return -1

def in_lab_registry(product):
    if not product:
        return False
    p = product.lower()
    for key in LAB_REGISTRY:
        if key in p:
            return True
    return False

def is_junk(detail):
    if not detail:
        return False
    hay = (detail.get("product") or "").lower()
    hay += " " + " ".join(detail.get("refs") or []).lower()
    return any(k in hay for k in JUNK_VENDORS)

def score_opportunity(triage, detail, poc_count):
    score = 0
    reasons = []
    if is_junk(detail):
        score -= 50
        reasons.append("vendor tutorial/projeto academico (depriorizado)")
    if triage.get("bounty"):
        score += 40
        reasons.append("triage=bounty")
    sev = triage.get("severity", "")
    if sev in ("HIGH", "CRITICAL"):
        score += 10
        reasons.append("severidade=" + sev)
    if poc_count == 0:
        score += 30
        reasons.append("SEM PoC publico (novidade!)")
    elif poc_count > 0:
        reasons.append("PoCs publicos: %d" % poc_count)
    if detail and in_lab_registry(detail.get("product")):
        score += 20
        reasons.append("reproduzivel em lab local")
    if score >= 70:
        level = "ALTA"
    elif score >= 40:
        level = "MEDIA"
    else:
        level = "BAIXA"
    return score, level, reasons

def process(core_state, zstate):
    triage_list = core_state.get("cve_triage", [])
    bounty_cves = [t for t in triage_list if t.get("bounty")]
    if not bounty_cves:
        log.info("nenhum CVE com bounty=SIM na triagem ainda")
        return
    for t in bounty_cves[-3:]:
        cid = t["id"]
        if cid in zstate["processed"]:
            continue
        log.info("analise profunda: %s", cid)
        detail = enrich_cve(cid)
        poc_count = check_public_poc(cid)
        score, level, reasons = score_opportunity(t, detail, poc_count)
        entry = {
            "id": cid,
            "severity": t.get("severity"),
            "score": score,
            "level": level,
            "product": detail.get("product") if detail else None,
            "version": detail.get("version") if detail else None,
            "poc_public_count": poc_count,
            "reasons": reasons,
            "ts": int(time.time()),
        }
        zstate["opportunities"].append(entry)
        zstate["processed"].append(cid)
        zstate["processed"] = zstate["processed"][-200:]
        zstate["opportunities"] = zstate["opportunities"][-100:]
        log.info("SCORE %s | %s | %d pts | %s | %s",
                 level, cid, score,
                 entry["product"] or "produto?",
                 "; ".join(reasons))
        if level == "ALTA":
            log.info(">>> OPORTUNIDADE ALTA: %s %s - candidata ao laboratorio (v0.6)",
                     entry["product"], entry["version"])
        time.sleep(6)
    save_zero_state(zstate)

def run(interval):
    log.info("=" * 56)
    log.info("SENTRIC ZERO v0.5 - inteligencia de vulnerabilidades")
    log.info("pare com: touch %s", STOP_FILE)
    log.info("=" * 56)
    while True:
        if os.path.exists(STOP_FILE):
            log.warning("STOP_ZERO detectado - encerrando")
            break
        core_state = load_core_state()
        if core_state:
            zstate = load_zero_state()
            process(core_state, zstate)
        else:
            log.warning("nucleo nao encontrado - rode o sentric_core primeiro")
        time.sleep(interval)

def main():
    ap = argparse.ArgumentParser(description="SENTRIC zero v0.5")
    ap.add_argument("--interval", type=int, default=1800)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    if args.once:
        core_state = load_core_state()
        if core_state:
            process(core_state, load_zero_state())
        return
    run(args.interval)

if __name__ == "__main__":
    main()
