#!/usr/bin/env python3
# sentric_lab.py - SENTRIC v0.7 - Laboratorio de validacao de exploits
# recon -> stack isolada -> PoC por LLM com diff do patch + API hints -> reparo automatico
import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("lab")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
import sentric_core as core

DATA_DIR = os.path.expanduser("~/sentric-core")
LAB_NET = "sentric-lab"
POC_DIR = os.path.join(DATA_DIR, "lab_pocs")
REPORT_DIR = os.path.join(DATA_DIR, "lab_reports")

LAB_IMAGE = os.environ.get("LAB_IMAGE",
    "ghcr.io/misp/misp-docker/misp-core:v2.5.45")
LAB_ADMIN_PASS = os.environ.get("LAB_ADMIN_PASS", "sentric-lab-2026")

def sh(cmd, timeout=120):
    if cmd and cmd[0] == "docker" and os.environ.get("LAB_SUDO") == "1":
        cmd = ["sudo"] + cmd
    log.debug("$ %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

def ensure_dirs():
    os.makedirs(POC_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)

def ensure_network():
    r = sh(["docker", "network", "inspect", LAB_NET])
    if r.returncode != 0:
        r = sh(["docker", "network", "create", LAB_NET])
        log.info("rede %s criada", LAB_NET)

def container_running(name):
    r = sh(["docker", "inspect", "-f", "{{.State.Running}}", name])
    return r.returncode == 0 and r.stdout.strip() == "true"

def wait_db(timeout=240):
    log.info("aguardando mysql ficar pronto...")
    t0 = time.time()
    while time.time() - t0 < timeout:
        r = sh(["docker", "exec", "db", "mysqladmin", "ping",
                "-h", "localhost", "-uroot", "-plabroot"], timeout=15)
        if r.returncode == 0 and "alive" in (r.stdout + r.stderr).lower():
            log.info("mysql db saudavel")
            time.sleep(5)
            return True
        time.sleep(5)
    return False

def start_target(name, image):
    if os.environ.get("LAB_REUSE") == "1" and container_running(name):
        log.info("reutilizando stack existente")
        return True
    sh(["docker", "rm", "-f", name, "db", "lab-redis"])
    log.info("subindo stack: mysql + redis + alvo")
    r = sh(["docker", "run", "-d", "--name", "db",
            "--network", LAB_NET,
            "-e", "MYSQL_ROOT_PASSWORD=labroot",
            "-e", "MYSQL_DATABASE=misp",
            "-e", "MYSQL_USER=misp",
            "-e", "MYSQL_PASSWORD=misppass",
            "mysql:8"], timeout=600)
    if r.returncode != 0:
        log.error("falha no mysql: %s", r.stderr[:300])
        return False
    if not wait_db():
        log.error("mysql nao respondeu")
        return False
    sh(["docker", "run", "-d", "--name", "lab-redis",
        "--network", LAB_NET, "redis:7-alpine",
        "redis-server", "--requirepass", "mispredis"], timeout=300)
    cmd = ["docker", "run", "-d", "--name", name,
           "--network", LAB_NET, "--restart", "unless-stopped",
           "-e", "MYSQL_HOST=db",
           "-e", "MYSQL_DATABASE=misp",
           "-e", "MYSQL_USER=misp",
           "-e", "MYSQL_PASSWORD=misppass",
           "-e", "MYSQL_ROOT_PASSWORD=labroot",
           "-e", "REDIS_HOST=lab-redis",
           "-e", "REDIS_PASSWORD=mispredis",
           "-e", "MISP_BASEURL=http://localhost",
           "-e", "MISP_ADMIN_EMAIL=admin@lab.sentric",
           "-e", "MISP_ADMIN_PASSPHRASE=" + LAB_ADMIN_PASS]
    cmd.append(image)
    r = sh(cmd, timeout=600)
    if r.returncode != 0:
        log.error("falha ao subir alvo: %s", r.stderr[:400])
        return False
    log.info("stack completa no ar")
    return True

def container_ip(name):
    r = sh(["docker", "inspect", "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name])
    return r.stdout.strip() if r.returncode == 0 else None

def wait_healthy(name, port, timeout=1200):
    log.info("aguardando o alvo ficar saudavel (ate %d min)...", timeout // 60)
    t0 = time.time()
    while time.time() - t0 < timeout:
        ip = container_ip(name)
        if ip:
            r = sh(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                    "--max-time", "5", "https://" + ip + ":" + str(port) + "/"])
            if r.stdout.strip() in ("000", ""):
                r = sh(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                        "--max-time", "5", "http://" + ip + ":" + str(port) + "/"])
            if r.returncode == 0 and r.stdout.strip() in ("200", "302", "301", "403"):
                lr = sh(["docker", "logs", name], timeout=30)
                if "MISP is now live" not in (lr.stdout + lr.stderr):
                    log.info("web respondeu mas init nao terminou, aguardando...")
                    time.sleep(10)
                    continue
                log.info("alvo saudavel em http://%s:%d/", ip, port)
                return ip
        time.sleep(10)
    log.error("alvo nao ficou saudavel a tempo")
    return None

def log_version(name):
    r = sh(["docker", "logs", name], timeout=60)
    for line in (r.stdout + r.stderr).splitlines():
        if "MISP | Version:" in line:
            log.info("VERSAO DO ALVO: %s", line.split(":", 1)[1].strip())

def destroy_target(name):
    sh(["docker", "rm", "-f", name, "db", "lab-redis"])
    log.info("stack destruida")

def get_target_info(target):
    zstate_file = os.path.join(DATA_DIR, "zero_state.json")
    info = {}
    if os.path.exists(zstate_file):
        with open(zstate_file, encoding="utf-8") as f:
            z = json.load(f)
        for op in z.get("opportunities", []):
            if op.get("id") == target:
                info = dict(op)
    cstate = core.load_state()
    for t in cstate.get("cve_triage", []):
        if t.get("id") == target:
            info["triage"] = t
    return info

PRELUDE = (
    "import os, sys, json, ssl, re\n"
    "import urllib.request, urllib.error, http.cookiejar\n"
    "from urllib.parse import urlparse, urlunparse, urlencode\n"
    "from urllib.request import Request, urlopen\n"
    "\n"
    "def _lab_opener():\n"
    "    ctx = ssl.create_default_context()\n"
    "    ctx.check_hostname = False\n"
    "    ctx.verify_mode = ssl.CERT_NONE\n"
    "    cj = http.cookiejar.CookieJar()\n"
    "    return urllib.request.build_opener(\n"
    "        urllib.request.HTTPSHandler(context=ctx),\n"
    "        urllib.request.HTTPCookieProcessor(cj))\n"
    "\n"
    "opener = _lab_opener()\n\n"
)

MISP_API_HINTS = (
    "MISP authentication: POST {url}/users/login with form fields "
    "data[User][email] and data[User][password]; keep and reuse the session "
    "cookie. Send header Accept: application/json for JSON. After login, GET "
    "{url}/users/view/me returns the admin auth key (User.authkey), usable as "
    "header Authorization: <authkey> for the REST API.\n"
    "CakePHP default routes: POST {url}/collections/add, GET "
    "{url}/collections/view/<id-or-uuid>, POST {url}/events/add, GET "
    "{url}/events/view/<id>.\n"
    "The vulnerability: the collection view template re-queries member event "
    "UUIDs without applying the caller event ACL (Event.uuid IN (...)), so a "
    "low-privilege user viewing a collection that references the UUID of "
    "another org private event can read that event full details."
)

POC_TEMPLATE_HINT = (
    "Use ONLY Python stdlib (urllib.request, json, ssl, sys, os, http.cookiejar).\n"
    "The global 'opener' (cookies, TLS certificate NOT verified, redirects "
    "handled) is ALREADY defined by the runtime - do NOT redefine it. Use "
    "opener.open(req) for every request. LAB_URL is an HTTPS base URL with a "
    "self-signed certificate.\n"
    "Read config from env: LAB_URL (base http://IP:PORT), LAB_ADMIN_PASS.\n"
    "Steps: authenticate as admin via the real login form; create a private "
    "event for a victim organisation; create a second ordinary user "
    "(attacker); as the attacker, abuse the vulnerability to access the "
    "private data.\n"
    "For every piece of unauthorized data read, print one line: LEAK:<field>=<value>\n"
    "Finish by printing exactly one line: RESULT:CONFIRMED or RESULT:NOT_CONFIRMED\n"
    "Print ONLY Python code, no explanations, no markdown fences."
)

def fetch_fix_diff(target):
    try:
        data = json.loads(core.http_get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + target))
        cve = data["vulnerabilities"][0]["cve"]
        refs = [r.get("url", "") for r in cve.get("references", [])]
    except Exception as e:
        log.warning("NVD refs falhou: %s", e)
        return ""
    for u in refs:
        m = re.search(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-f]+)", u)
        if m:
            api = "https://api.github.com/repos/" + m.group(1) + "/commits/" + m.group(2)
            try:
                d = json.loads(core.http_get(api))
                patches = []
                for f in d.get("files", []):
                    if f.get("patch"):
                        patches.append("### " + f["filename"] + "\n" + f["patch"][:2500])
                return "\n\n".join(patches)[:6000]
            except Exception as e:
                log.warning("commit fetch falhou: %s", e)
    return ""

def build_poc_prompt(target, info, url, diff_text, feedback):
    triage = info.get("triage", {})
    parts = [
        "You are an authorized security researcher. This is a DEFENSIVE "
        "validation test in an isolated laboratory that I own and operate "
        "locally (a Docker container with intentionally vulnerable software). "
        "The CVE is public, the vendor fix is already released, and the result "
        "is for coordinated vulnerability disclosure.",
        "Write a Python 3 PoC for " + target + ".",
        "Product: " + str(info.get("product") or "MISP") +
        " version " + str(info.get("version") or "<= 2.5.45"),
        "Vulnerability description:",
        (triage.get("reason") or info.get("note") or "authorization bypass / IDOR")[:800],
        "Analysis note: " + json.dumps({k: info.get(k) for k in
                                        ("severity", "score", "level")}),
        MISP_API_HINTS.format(url=url),
        "Vendor fix commit diff (shows the vulnerable code path):",
        diff_text or "(diff indisponivel, use a descricao)",
        "Target lab URL: " + url,
        "Admin credentials: admin@lab.sentric / " + LAB_ADMIN_PASS,
        POC_TEMPLATE_HINT,
    ]
    if feedback:
        parts.append("Previous attempt failed. Its output/error:")
        parts.append(feedback)
        parts.append("Fix the script accordingly. Keep the LEAK:/RESULT: protocol.")
    return "\n".join(parts)

def llm_write_poc(target, info, url, diff_text, feedback):
    cfg = core.load_config()
    prompt = build_poc_prompt(target, info, url, diff_text, feedback)
    code = ""
    for attempt in (1, 2):
        model = cfg["llm_model"] if attempt == 1 else "qwen2.5:1.5b"
        try:
            raw = core.ask_llm(prompt, model)
        except Exception as e:
            log.error("LLM falhou ao gerar PoC: %s", e)
            return None
        code = raw.strip()
        if code.startswith("```"):
            lines = code.splitlines()
            lines = [l for l in lines if not l.strip().startswith("```")]
            code = "\n".join(lines)
        lines = code.splitlines()
        while lines:
            try:
                compile("\n".join(lines), "<poc>", "exec")
                break
            except SyntaxError:
                lines.pop()
        code = "\n".join(lines)
        if "import os" not in code:
            code = PRELUDE + code
        if len(code.splitlines()) >= 10:
            break
        log.warning("PoC muito curto (%d linhas) com %s, tentativa %d/2",
                    len(code.splitlines()), model, attempt)
        prompt += ("\n\nYour previous answer was too short or invalid. "
                   "Output ONLY the complete Python script, at least 40 lines.")
    if len(code.splitlines()) < 10:
        log.error("LLM nao produziu um PoC utilizavel")
        return None
    path = os.path.join(POC_DIR, target.replace("/", "_") + ".py")
    with open(path, "w", encoding="utf-8") as f:
        f.write(code + "\n")
    log.info("PoC escrito em %s (%d linhas)", path, len(code.splitlines()))
    return path

def run_poc(path, url):
    env = dict(os.environ)
    env["LAB_URL"] = url
    env["LAB_ADMIN_PASS"] = LAB_ADMIN_PASS
    log.info("executando PoC contra %s ...", url)
    try:
        r = subprocess.run([sys.executable, path], capture_output=True,
                           text=True, timeout=240, env=env)
    except subprocess.TimeoutExpired:
        log.error("PoC estourou o timeout (240s)")
        return "", "TIMEOUT"
    return r.stdout + "\n[stderr]\n" + r.stderr, r.returncode

def judge(output):
    if "RESULT:CONFIRMED" in output and "LEAK:" in output:
        return "CONFIRMED"
    if "RESULT:NOT_CONFIRMED" in output:
        return "NOT_CONFIRMED"
    return "INCONCLUSIVO"

def write_report(target, info, url, poc_path, output, verdict):
    path = os.path.join(REPORT_DIR, target.replace("/", "_") + ".md")
    leaks = [l for l in output.splitlines() if l.startswith("LEAK:")]
    text = [
        "# Relatorio de Validacao - " + target,
        "",
        "- data: " + datetime.now().isoformat(timespec="seconds"),
        "- alvo: " + str(info.get("product") or "?") + " " + str(info.get("version") or ""),
        "- laboratorio: " + url + " (rede isolada " + LAB_NET + ")",
        "- veredito: **" + verdict + "**",
        "- score original: " + str(info.get("score")),
        "",
        "## Descricao da vulnerabilidade",
        "",
        str(info.get("triage", {}).get("reason") or info.get("note") or ""),
        "",
        "## Evidencias de vazamento",
        "",
    ]
    text += ["    " + l for l in leaks] or ["    (nenhum LEAK capturado)"]
    text += [
        "",
        "## Saida completa do PoC",
        "",
        "```",
        output[:4000],
        "```",
        "",
        "## Como reproduzir",
        "",
        "1. Subir o alvo: docker run --network " + LAB_NET + " ...",
        "2. Executar: LAB_URL=" + url + " python3 " + str(poc_path),
        "",
        "## Notas",
        "",
        "Relatorio gerado automaticamente por SENTRIC v0.7.",
        "Revisao humana obrigatoria antes de qualquer submissao.",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(text) + "\n")
    log.info("relatorio: %s", path)
    return path

def mark_confirmed(target):
    zpath = os.path.join(DATA_DIR, "zero_state.json")
    if not os.path.exists(zpath):
        return
    with open(zpath, encoding="utf-8") as f:
        z = json.load(f)
    for op in z.get("opportunities", []):
        if op.get("id") == target:
            op["lab_confirmed"] = True
            op["confirmed_at"] = int(time.time())
    with open(zpath + ".tmp", "w", encoding="utf-8") as f:
        json.dump(z, f, indent=2)
    os.replace(zpath + ".tmp", zpath)

def lab_bootstrap(name):
    log.info("aplicando bootstrap no alvo...")
    sh(["docker", "exec", name, "sh", "-c",
        "grep -rl 'server_name' /etc/nginx/ | while read f; do sed -i 's/server_name .*/server_name _;/' $f; done; nginx -s reload"], timeout=60)
    sh(["docker", "exec", name, "sh", "-c",
        "sed -i \"s/'enable_themes' => false,/'enable_themes' => true, 'default_theme' => 'UiBeta',/\" /var/www/MISP/app/Config/config.php; rm -rf /var/www/MISP/app/tmp/cache/persistent/*"], timeout=60)
    key = "SENTRICADMIN" + "1" * 28
    r = sh(["docker", "exec", name,
            "/var/www/MISP/app/Console/cake", "user", "change_authkey",
            "admin@admin.test", key], timeout=60)
    log.info("bootstrap: %s", (r.stdout + r.stderr).strip()[:120])

def run(target, destroy):
    ensure_dirs()
    info = get_target_info(target)
    log.info("alvo: %s | %s %s", target,
             info.get("product"), info.get("version"))
    ensure_network()
    name = "lab-" + target.lower().replace("-", "")
    if not start_target(name, LAB_IMAGE):
        log.error("nao foi possivel subir o laboratorio")
        return
    ip = wait_healthy(name, 80)
    if not ip:
        log.error("lab nao respondeu - veja: sudo docker logs %s", name)
        return
    log_version(name)
    lab_bootstrap(name)
    url = "https://" + ip
    diff_text = fetch_fix_diff(target)
    feedback = ""
    verdict = "INCONCLUSIVO"
    output = ""
    poc = None
    for rnd in (1, 2, 3):
        poc = llm_write_poc(target, info, url, diff_text, feedback)
        if not poc:
            break
        output, _ = run_poc(poc, url)
        verdict = judge(output)
        log.info("VEREDITO (rodada %d): %s", rnd, verdict)
        if verdict in ("CONFIRMED", "NOT_CONFIRMED"):
            break
        feedback = output[-1500:]
    write_report(target, info, url, poc, output, verdict)
    if verdict == "CONFIRMED":
        mark_confirmed(target)
        log.info(">>> %s CONFIRMADA EM LAB - bounty ready (apos revisao humana)", target)
    if destroy:
        destroy_target(name)

def main():
    ap = argparse.ArgumentParser(description="SENTRIC lab v0.7")
    ap.add_argument("--target", required=True, help="ex: CVE-2026-86283")
    ap.add_argument("--destroy", action="store_true",
                    help="destroi a stack apos o teste (padrao: mantem)")
    args = ap.parse_args()
    run(args.target, args.destroy)

if __name__ == "__main__":
    main()
