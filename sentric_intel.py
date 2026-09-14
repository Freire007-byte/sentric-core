#!/usr/bin/env python3
# sentric_intel.py - SENTRIC v0.8 - inteligencia multi-fonte p/ filtrar CVEs de retorno real
import json
import logging
import os
import sys
import time
import urllib.request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("intel")

DATA_DIR = os.path.expanduser("~/sentric-core")
CACHE_FILE = os.path.join(DATA_DIR, "intel_cache.json")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NOMI_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"

KEV_HITS = None

def http_get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "sentric-intel/0.8"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        log.warning("http falhou %s: %s", url[:70], e)
        return 0, ""

def load_kev():
    global KEV_HITS
    if KEV_HITS is not None:
        return KEV_HITS
    code, raw = http_get(KEV_URL, timeout=30)
    if code != 200:
        log.warning("KEV feed falhou: %s", code)
        KEV_HITS = set()
        return KEV_HITS
    data = json.loads(raw)
    KEV_HITS = set(v.get("cveID", "") for v in data.get("vulnerabilities", []))
    log.info("KEV carregado: %d CVEs sendo exploradas na vida real", len(KEV_HITS))
    return KEV_HITS

def epss_score(cve):
    code, raw = http_get(EPSS_URL + "?cve=" + cve, timeout=15)
    if code != 200:
        return None
    try:
        d = json.loads(raw)
        vals = d.get("data", [])
        if vals:
            return float(vals[0][1])
    except Exception:
        pass
    return None

def poc_public_exists(cve):
    year = cve.split("-")[1]
    code, _ = http_get(NOMI_URL + "/" + year + "/" + cve + ".json", timeout=10)
    return code == 200

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    tmp = CACHE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cache, f)
    os.replace(tmp, CACHE_FILE)

# vendors com bug bounty program (curado; expandir depois via disclose.io)
BOUNTY_VENDORS = ("google", "microsoft", "cloudflare", "github", "gitlab",
                  "proton", "standardnotes", "standard notes", "mozilla",
                  "oracle", "adobe", "apple", "facebook", "meta", "twitter",
                  "x corp", "shopify", "paypal", "coinbase", "binance",
                  "hashicorp", "vmware", "citrix", "fortinet", "palo alto",
                  "atlassian", "slack", "zoom", "dropbox", "spotify",
                  "curl", "openssl", "apache", "nginx", "mozilla")

REAL_VENDORS = ("misp", "wordpress", "drupal", "joomla", "laravel", "symfony",
                "django", "rails", "nodejs", "node.js", "react", "angular",
                "kubernetes", "docker", "grafana", "prometheus", "jenkins",
                "gitlab", "nexus", "sonarqube", "elasticsearch", "kibana",
                "log4j", "openssl", "openssh", "apache", "nginx", "tomcat",
                "redis", "mysql", "postgresql", "mongodb", "rabbitmq",
                "kafka", "zookeeper", "consul", "vault", "cisco", "juniper")

JUNK = ("sourcecodester", "code-projects", "mstfakts", "mstafaks",
        "hotel and tourism", "college-management", "phpgurukul",
        "projectworlds", "codeastro", "itsourcecode")

def vendor_score(product, desc):
    hay = ((product or "") + " " + (desc or "")).lower()
    if any(j in hay for j in JUNK):
        return -50, "vendor lixo/tutorial"
    if any(b in hay for b in BOUNTY_VENDORS):
        return 20, "tem bug bounty program"
    if any(r in hay for r in REAL_VENDORS):
        return 15, "produto real conhecido"
    return 0, "produto nao classificado"

def intel_score(cve, product, desc, severity, cache):
    score = 0
    reasons = []
    if cve in load_kev():
        score += 25
        reasons.append("CISA KEV (exploitada na vida real)")
    epss = cache.get(cve, {}).get("epss")
    if epss is None:
        epss = epss_score(cve)
        cache.setdefault(cve, {})["epss"] = epss
        time.sleep(1)
    if epss is not None and epss >= 0.5:
        score += 20
        reasons.append("EPSS %.2f (alta probabilidade)" % epss)
    vs, vreason = vendor_score(product, desc)
    score += vs
    reasons.append(vreason)
    fresh = cache.get(cve, {}).get("fresh")
    if fresh is None:
        fresh = not poc_public_exists(cve)
        cache.setdefault(cve, {})["fresh"] = fresh
        time.sleep(1)
    if fresh:
        score += 15
        reasons.append("SEM PoC publico (janela de novidade)")
    else:
        score -= 30
        reasons.append("PoC publico ja existe (saturada)")
    if severity in ("HIGH", "CRITICAL"):
        score += 10
        reasons.append("severidade " + severity)
    return score, reasons, epss, fresh

def analyze_from_core(limit=10):
    sys.path.insert(0, DATA_DIR)
    import sentric_core as core
    state = core.load_state()
    triage = state.get("cve_triage", [])
    cache = load_cache()
    results = []
    for t in triage[-limit:]:
        cve = t["id"]
        score, reasons, epss, fresh = intel_score(
            cve, t.get("product"), t.get("reason", ""),
            t.get("severity", ""), cache)
        save_cache(cache)
        verdict = "CAÇAR" if score >= 40 else ("observar" if score >= 10 else "ignorar")
        log.info("%s | score %d | %s | %s", cve, score, verdict,
                 "; ".join(reasons))
        results.append({"id": cve, "score": score, "verdict": verdict,
                        "reasons": reasons})
    return results

def main():
    log.info("=" * 56)
    log.info("SENTRIC INTEL v0.8 - multi-fonte (KEV/EPSS/nomi-sec/vendor)")
    log.info("=" * 56)
    load_kev()
    analyze_from_core()

if __name__ == "__main__":
    main()
