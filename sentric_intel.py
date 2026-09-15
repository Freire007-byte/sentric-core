#!/usr/bin/env python3
# sentric_intel.py - SENTRIC v0.8 - inteligencia multi-fonte p/ filtrar CVEs de retorno real
import json
import logging
import os
import subprocess
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
BOUNTY_TOP = ("apple", "google", "samsung", "microsoft", "meta",
              "nvidia", "tesla", "amazon", "intel", "cisco", "oracle",
              "adobe", "paypal", "shopify", "uber", "airbnb", "netflix",
              "ethereum", "solana", "uniswap", "aave", "lido", "polygon",
              "arbitrum", "optimism", "chainlink", "starknet", "near",
              "cosmos", "avalanche", "makerdao", "curve", "compound",
              "binance", "coinbase", "kraken", "okx", "ledger", "trezor",
              "metamask", "phantom", "walletconnect", "openai", "anthropic")

BOUNTY_VENDORS = ("google", "microsoft", "cloudflare", "github", "gitlab",
                  "proton", "standardnotes", "standard notes", "mozilla",
                  "oracle", "adobe", "apple", "meta", "shopify", "paypal",
                  "hashicorp", "vmware", "citrix", "fortinet", "palo alto",
                  "atlassian", "slack", "zoom", "dropbox", "spotify",
                  "curl", "openssl", "apache", "nginx", "jetbrains",
                  "samsung", "nvidia", "intel", "dell", "lenovo", "asus",
                  "netgear", "ubiquiti", "mikrotik", "sophos", "f5",
                  "salesforce", "zendesk", "stripe", "airbnb", "uber",
                  "lyft", "doordash", "spotify", "netflix", "tiktok",
                  "snap", "pinterest", "reddit", "discord", "telegram",
                  "signal", "mongodb", "redis", "confluent", "datadog",
                  "elastic", "splunk", "rapid7", "tenable", "qualys",
                  "wordfence", "automattic", "squarespace", "wix")

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
    if any(b in hay for b in BOUNTY_TOP):
        return 30, "MEGA-PAGADOR (ate milhoes $)"
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



AUTOPILOT_STATE = os.path.join(DATA_DIR, "autopilot_state.json")
LAB_WISHLIST = os.path.join(DATA_DIR, "lab_wishlist.json")

def autopilot_check():
    bt = os.path.join(DATA_DIR, "bounty_targets.json")
    if not os.path.exists(bt):
        return
    targets = json.load(open(bt, encoding="utf-8"))
    state = {}
    if os.path.exists(AUTOPILOT_STATE):
        state = json.load(open(AUTOPILOT_STATE, encoding="utf-8"))
    today = time.strftime("%Y-%m-%d")
    if state.get("day") != today:
        state["day"] = today
        state["daily_count"] = 0
    state.setdefault("done", [])
    wish = []
    if os.path.exists(LAB_WISHLIST):
        wish = json.load(open(LAB_WISHLIST, encoding="utf-8"))
    for t in targets:
        if t["id"] in state["done"]:
            continue
        if state.get("daily_count", 0) >= 1:
            log.info("autopilot: limite diario de labs atingido")
            break
        hay = (t.get("product") or "").lower()
        stack = None
        if "misp" in hay:
            stack = "misp"
        if stack:
            state["done"].append(t["id"])
            state["daily_count"] = state.get("daily_count", 0) + 1
            log.info(">>> AUTOPILOT: bounty %s caiu no funil -> disparando lab (stack %s)", t["id"], stack)
            logfile = open(os.path.join(DATA_DIR, "lab_autopilot.log"), "ab")
            env = dict(os.environ)
            env["LAB_SUDO"] = "1"
            subprocess.Popen(
                ["python3", os.path.join(DATA_DIR, "sentric_lab.py"),
                 "--target", t["id"]],
                env=env, stdout=logfile, stderr=subprocess.STDOUT)
        else:
            log.info("autopilot: %s sem stack de lab conhecida -> wishlist", t["id"])
            if t["id"] not in [w.get("id") for w in wish]:
                wish.append({"id": t["id"], "product": t.get("product"),
                             "score": t.get("score")})
    with open(AUTOPILOT_STATE + ".tmp", "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(AUTOPILOT_STATE + ".tmp", AUTOPILOT_STATE)
    with open(LAB_WISHLIST + ".tmp", "w", encoding="utf-8") as f:
        json.dump(wish, f, indent=2)
    os.replace(LAB_WISHLIST + ".tmp", LAB_WISHLIST)

def run_loop(interval=1800):
    log.info("SENTRIC INTEL em modo continuo (a cada %d min)", interval // 60)
    while True:
        if os.path.exists(os.path.join(DATA_DIR, "STOP_INTEL")):
            log.warning("STOP_INTEL detectado - encerrando")
            break
        load_kev()
        bounty_scan()
        kev_bounty_hunt()
        defense_scan()
        autopilot_check()
        time.sleep(interval)

def main():
    log.info("=" * 56)
    log.info("SENTRIC INTEL v0.8 - multi-fonte (KEV/EPSS/nomi-sec/vendor)")
    log.info("=" * 56)
    load_kev()
    analyze_from_core()
    log.info("=" * 56)
    log.info("CAÇA BOUNTY: fresca + sem patch + vendor paga + sem PoC")
    log.info("=" * 56)
    bounty_scan()
    log.info("=" * 56)
    log.info("VARREDURA DEFESA/GOV")
    log.info("=" * 56)
    defense_scan()
    for k, v in REPORT_CHANNELS.items():
        log.info("canal %-16s %s", k, v)



NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cve_detail(cve):
    code, raw = http_get(NVD_URL + "?cveId=" + cve, timeout=20)
    if code != 200:
        return None
    try:
        c = json.loads(raw)["vulnerabilities"][0]["cve"]
        refs = c.get("references", [])
        desc = ""
        for d in c.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        return {"published": c.get("published", ""), "refs": refs, "desc": desc}
    except Exception:
        return None

def patch_evidence(detail):
    if not detail:
        return False
    desc = detail.get("desc", "").lower()
    if "fixed in" in desc or "has been fixed" in desc or "resolved in" in desc:
        return True
    for r in detail.get("refs", []):
        url = r.get("url", "").lower()
        tags = " ".join(r.get("tags", [])).lower()
        if "patch" in tags:
            return True
        if "commit" in url and ("fix" in url or "security" in url):
            return True
        if "github.com" in url and "/security/advisories" in url:
            return True
    return False

def kev_bounty_hunt(max_age=60):
    code, raw = http_get(KEV_URL, timeout=30)
    if code != 200:
        return
    try:
        vulns = json.loads(raw).get("vulnerabilities", [])
    except Exception:
        return
    cache = load_cache()
    bt = os.path.join(DATA_DIR, "bounty_targets.json")
    targets = []
    if os.path.exists(bt):
        targets = json.load(open(bt, encoding="utf-8"))
    have = set(t.get("id") for t in targets)
    novos = 0
    for v in vulns:
        cve = v.get("cveID", "")
        vendor = v.get("vendorProject", "") or ""
        product = v.get("product", "") or ""
        added = v.get("dateAdded", "")
        try:
            age = (time.time() - time.mktime(time.strptime(added, "%Y-%m-%d"))) / 86400
        except Exception:
            age = 9999
        if age > max_age or cve in have:
            continue
        vs, vreason = vendor_score(product, vendor + " " + product)
        if vs < 20:
            continue
        fresh = cache.get(cve, {}).get("fresh")
        if fresh is None:
            fresh = not poc_public_exists(cve)
            cache.setdefault(cve, {})["fresh"] = fresh
            time.sleep(0.5)
        save_cache(cache)
        score = vs + 25 + (10 if fresh else 0)
        note = "CISA KEV (%dd) + %s%s" % (int(age), vreason,
              "; SEM PoC publico" if fresh else "; PoC existe (credito/reproducao)")
        targets.append({"id": cve, "score": score, "age_days": int(age),
                        "severity": "KEV", "product": product, "note": note})
        have.add(cve)
        novos += 1
        log.info(">>> ALVO BOUNTY-KEV: %s | %s | %d pts | %s", cve, product, score, note)
    if novos:
        targets.sort(key=lambda x: -x.get("score", 0))
        with open(bt + ".tmp", "w", encoding="utf-8") as f:
            json.dump(targets, f, indent=2)
        os.replace(bt + ".tmp", bt)
    log.info("kev_bounty_hunt: %d novos alvos (total %d)", novos, len(targets))


def bounty_scan(limit=40):
    sys.path.insert(0, DATA_DIR)
    import sentric_core as core
    state = core.load_state()
    cache = load_cache()
    targets = []
    for t in state.get("cve_triage", [])[-limit:]:
        cve = t["id"]
        vs, vreason = vendor_score(t.get("product"), t.get("reason", ""))
        if vs < 20:
            continue
        detail = cache.get(cve, {}).get("detail")
        if detail is None:
            d = fetch_cve_detail(cve)
            detail = d or {}
            cache.setdefault(cve, {})["detail"] = detail
            time.sleep(1)
        published = detail.get("published", "")
        age_days = 9999
        if published:
            try:
                pub = time.strptime(published[:19], "%Y-%m-%dT%H:%M:%S")
                age_days = (time.time() - time.mktime(pub)) / 86400
            except Exception:
                pass
        patched = patch_evidence(detail) if detail else False
        fresh = cache.get(cve, {}).get("fresh")
        if fresh is None:
            fresh = not poc_public_exists(cve)
            cache.setdefault(cve, {})["fresh"] = fresh
            time.sleep(1)
        save_cache(cache)
        if age_days < 45 and not patched and fresh:
            score = 30 + (15 if age_days < 7 else 0) + (10 if t.get("severity") in ("HIGH", "CRITICAL") else 0)
            targets.append({"id": cve, "score": score, "age_days": int(age_days),
                            "severity": t.get("severity"),
                            "note": "BOUNTY: fresca (%dd), sem patch evidente, sem PoC, vendor paga" % int(age_days)})
            log.info(">>> ALVO BOUNTY: %s | %dd | %s | %s pts", cve, age_days,
                     t.get("severity"), score)
    targets.sort(key=lambda x: -x["score"])
    out = os.path.join(DATA_DIR, "bounty_targets.json")
    with open(out + ".tmp", "w", encoding="utf-8") as f:
        json.dump(targets, f, indent=2)
    os.replace(out + ".tmp", out)
    log.info("bounty_targets.json: %d alvos de alto retorno", len(targets))
    return targets


# alvos defesa/gov: contractors, software de seguranca usado por governos
GOV_DEFENSE = ("palantir", "anduril", "lockheed", "bae systems", "northrop",
               "raytheon", "rtx", "thales", "airbus", "leonardo", "indra",
               "saab", "rheinmetall", "general dynamics", "l3harris",
               "boeing defense", "dassault", "israel aerospace", "rafael",
               "elbit", "havelsan", "aselsan", "roksanda",
               "misp", "opencti", "thehive", "cortex", "velociraptor",
               "osquery", "wazuh", "zeek", "suricata", "snort", "arkime",
               "timesketch", "plaso", "volatility", "ghidra", "yara",
               "sigma", "ossec", "falco", "elastic security", "splunk",
               "qradar", "mcafee", "trellix", "sentinelone", "crowdstrike",
               "huntress", "cynet", "perimeter81", "tailscale", "zerotier")

# canais oficiais de reporte (divulgacao coordenada)
REPORT_CHANNELS = {
    "cncs_portugal": "CERT nacional de Portugal — vuln.ciber.gov.pt",
    "cert_eu": "CERT-EU (instituicoes UE) — cert.europa.eu",
    "dod_vdp": "US DoD Vulnerability Disclosure — vulnerability.mil (PAGA bounty)",
    "hackthepentagon": "Hack the Pentagon (HackerOne) — programa pago",
    "first_cert": "Lista mundial de CERTs — first.org/members/teams",
    "intigriti": "intigriti.com — programs publicos incl. gov-adjacentes",
}

def defense_scan(limit=40):
    sys.path.insert(0, DATA_DIR)
    import sentric_core as core
    state = core.load_state()
    hits = []
    for t in state.get("cve_triage", [])[-limit:]:
        hay = ((t.get("product") or "") + " " + (t.get("reason") or "")).lower()
        for g in GOV_DEFENSE:
            if g in hay:
                hits.append({"id": t["id"], "severity": t.get("severity"),
                             "match": g})
                log.info(">>> ALVO DEFESA/GOV: %s | %s | match: %s",
                         t["id"], t.get("severity"), g)
                break
    out = os.path.join(DATA_DIR, "gov_defense_targets.json")
    with open(out + ".tmp", "w", encoding="utf-8") as f:
        json.dump(hits, f, indent=2)
    os.replace(out + ".tmp", out)
    if not hits:
        log.info("defesa/gov: nenhum alvo no radar atual")
    return hits


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=1800)
    args = ap.parse_args()
    if args.loop:
        run_loop(args.interval)
    else:
        main()
