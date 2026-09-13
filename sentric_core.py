#!/usr/bin/env python3
import socket
socket.setdefaulttimeout(10)
# sentric_core.py - SENTRIC v0.3 - sobrevivencia multi-fonte
# modulos: tesouraria | mercados | CVE+LLM triage | staking | salario trading
import argparse
import csv
import io
import json
import logging
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timedelta

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("sentric")

NAME = "Sentric"
VERSION = "0.3.0"
DATA_DIR = os.path.expanduser("~/sentric-core")
KEY_FILE = os.path.join(DATA_DIR, "sentric_key.json")
STATE_FILE = os.path.join(DATA_DIR, "sentric_state.json")
CONFIG_FILE = os.path.join(DATA_DIR, "sentric_config.json")
IDENTITY_FILE = os.path.join(DATA_DIR, "AGENT.md")
STOP_FILE = os.path.join(DATA_DIR, "STOP")
RPC_URL = "https://api.mainnet-beta.solana.com"
# USDT (SPL) na Solana - confira o mint em solscan.io antes de enviar
USDT_MINT = "Es9vMFrzaCERmJfrF4H2FYD4PFhF5gs1fV2g6UJwBb2v"
LLM_URL = "http://localhost:11434/api/generate"

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MARKETS = ("xauusd", "cl.f", "btcusd")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULT_CONFIG = {
    "min_reserve_sol": 0.01,
    "daily_spend_limit_sol": 0.05,
    "scan_markets_every_cycles": 3,
    "scan_cve_every_cycles": 10,
    "llm_model": "qwen2.5:1.5b",
    "staking_min_excess_sol": 1.0,
    "trading_state_path": os.path.expanduser("~/local-trader-ai/state.json"),
    "modules": {
        "treasury": True,
        "markets": True,
        "cve_recon": True,
        "llm_triage": True,
        "staking": True,
        "trading_salary": True,
    },
}

# ---------------- identidade ----------------

def b58encode(data):
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + out

def load_or_create_keypair():
    try:
        from nacl.signing import SigningKey
    except ImportError:
        log.error("PyNaCl nao instalado. Rode: pip install pynacl")
        sys.exit(1)
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, encoding="utf-8") as f:
            seed = bytes.fromhex(json.load(f)["seed_hex"])
        sk = SigningKey(seed)
    else:
        sk = SigningKey.generate()
        with open(KEY_FILE, "w", encoding="utf-8") as f:
            json.dump({"seed_hex": sk.encode().hex()}, f)
        os.chmod(KEY_FILE, 0o600)
        log.info("NOVA identidade SENTRIC criada")
    return sk, b58encode(sk.verify_key.encode())

def rpc_call(method, params):
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "method": method, "params": params,
    }).encode()
    req = urllib.request.Request(RPC_URL, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())
    if "error" in data:
        raise RuntimeError(str(data["error"]))
    return data["result"]

def get_balance(address):
    return rpc_call("getBalance", [address])["value"] / 1e9

def get_token_balance(address, mint):
    params = [address, {"mint": mint}, {"encoding": "jsonParsed"}]
    result = rpc_call("getTokenAccountsByOwner", params)
    total = 0.0
    for item in result.get("value", []):
        info = item["account"]["data"]["parsed"]["info"]
        total += float(info["tokenAmount"]["uiAmount"])
    return total

# ---------------- llm local ----------------

def ask_llm(prompt, model):
    body = json.dumps({
        "model": model, "prompt": prompt, "stream": False,
    }).encode()
    req = urllib.request.Request(LLM_URL, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        data = json.loads(resp.read().decode())
    return data.get("response", "").strip()

# ---------------- estado ----------------

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {
        "created": datetime.now().isoformat(timespec="seconds"),
        "address": None,
        "heartbeats": 0,
        "cycles": 0,
        "balance_history": [],
        "lifetime_earned": 0.0,
        "lifetime_spent": 0.0,
        "spent_today": 0.0,
        "spend_day": datetime.now().strftime("%Y-%m-%d"),
        "markets": {},
        "opportunities": [],
        "cves_seen": 0,
        "cve_triage": [],
        "last_trading_cash": None,
        "last_balance": 0.0,
    }

def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_FILE)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
        merged = dict(DEFAULT_CONFIG)
        merged.update({k: v for k, v in cfg.items() if k != "modules"})
        mods = dict(DEFAULT_CONFIG["modules"])
        mods.update(cfg.get("modules", {}))
        merged["modules"] = mods
        return merged
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    return dict(DEFAULT_CONFIG)

def write_identity(address):
    text = [
        "# " + NAME + " - Manifesto de Identidade",
        "",
        "- nome: " + NAME,
        "- versao: " + VERSION,
        "- rede: Solana mainnet",
        "- endereco: " + address,
        "- diretriz: sobreviver e gerar ativos em multiplas fontes",
        "",
        "## Modulos",
        "",
        "- treasury: saldo, fluxo, score de sobrevivencia",
        "- markets: ouro, petroleo, BTC com RSI diario real",
        "- cve_recon: varredura NVD + triagem por LLM local",
        "- staking: estimativa de yield on-chain e plano de stake",
        "- trading_salary: lucro do bot local-trader-ai vira renda",
        "- spend_policy: limites diarios e reserva minima",
        "",
        "## Regras (nao negociaveis)",
        "",
        "- chave privada nunca sai da maquina",
        "- gasto acima do limite ou abaixo da reserva: NEGADO",
        "- LLM local apenas (dados nunca saem)",
        "- humano manda: arquivo STOP para tudo",
    ]
    with open(IDENTITY_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(text) + "\n")

# ---------------- mercados ----------------

def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode()

YMAP = {"xauusd": "GC=F", "cl.f": "CL=F", "btcusd": "BTC-USD"}

def fetch_daily_closes(symbol, limit=60):
    url = ("https://query1.finance.yahoo.com/v8/finance/chart/"
           + YMAP[symbol] + "?interval=1d&range=6mo")
    data = json.loads(http_get(url))
    quote = data["chart"]["result"][0]["indicators"]["quote"][0]
    closes = [c for c in quote["close"] if c is not None]
    return closes[-limit:]

def compute_rsi(closes, period=14):
    if len(closes) < period + 1:
        return 50.0
    gains, losses = [], []
    for i in range(1, len(closes)):
        diff = closes[i] - closes[i - 1]
        gains.append(max(diff, 0.0))
        losses.append(max(-diff, 0.0))
    ag = sum(gains[:period]) / period
    al = sum(losses[:period]) / period
    for i in range(period, len(gains)):
        ag = (ag * (period - 1) + gains[i]) / period
        al = (al * (period - 1) + losses[i]) / period
    if al == 0:
        return 100.0
    return 100.0 - 100.0 / (1.0 + ag / al)

def scan_markets(state):
    for symbol in MARKETS:
        try:
            closes = fetch_daily_closes(symbol)
        except Exception as e:
            log.warning("mercado %s falhou: %s", symbol, e)
            continue
        if len(closes) < 2:
            log.warning("mercado %s: sem dados do stooq", symbol)
            continue
        price = closes[-1]
        rsi = compute_rsi(closes)
        change24 = (price - closes[-2]) / closes[-2] * 100
        bias = "NEUTRO"
        if rsi >= 70:
            bias = "SOBRECOMPRADO (venda/short)"
        elif rsi <= 30:
            bias = "SOBREVENDIDO (compra/long)"
        state["markets"][symbol] = {
            "price": round(price, 2),
            "rsi": round(rsi, 1),
            "change_pct": round(change24, 2),
        }
        log.info("MERCADO %s: %.2f | RSI %.1f | 24h %+.2f%% | %s",
                 symbol.upper(), price, rsi, change24, bias)
        if rsi >= 70 or rsi <= 30:
            state["opportunities"].append({
                "ts": int(time.time()), "source": "market",
                "asset": symbol, "rsi": round(rsi, 1), "note": bias,
            })
    state["opportunities"] = state["opportunities"][-100:]

# ---------------- CVE + triagem LLM ----------------

TRIAGE_PROMPT = (
    "You are a security analyst triaging CVEs for bug bounty potential.\n"
    "CVE: {cid}\n"
    "Description: {desc}\n"
    "Reply EXACTLY in one line:\n"
    "severity=<LOW|MEDIUM|HIGH|CRITICAL> bounty=<yes|no> reason=<max 12 words>"
)

def triage_cve(cid, desc, model):
    prompt = TRIAGE_PROMPT.format(cid=cid, desc=desc[:600])
    try:
        raw = ask_llm(prompt, model)
    except Exception as e:
        log.warning("LLM triage falhou para %s: %s", cid, e)
        return None
    sev = re.search(r"severity=(\w+)", raw)
    bounty = re.search(r"bounty=(\w+)", raw)
    reason = re.search(r"reason=(.+)", raw)
    return {
        "id": cid,
        "severity": sev.group(1).upper() if sev else "UNKNOWN",
        "bounty": (bounty.group(1).lower() == "yes") if bounty else False,
        "reason": reason.group(1).strip()[:160] if reason else raw[:160],
        "ts": int(time.time()),
    }

def scan_cves(state, config):
    start = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000")
    url = (NVD_URL + "?pubStartDate=" + start + "&pubEndDate=" + end
           + "&resultsPerPage=5")
    try:
        data = json.loads(http_get(url))
    except Exception as e:
        log.warning("NVD falhou: %s", e)
        return
    vulns = data.get("vulnerabilities", [])
    state["cves_seen"] += len(vulns)
    use_llm = config["modules"].get("llm_triage", True)
    for v in vulns:
        cve = v.get("cve", {})
        cid = cve.get("id", "?")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:400]
                break
        if use_llm:
            t = triage_cve(cid, desc, config["llm_model"])
            if t:
                state["cve_triage"].append(t)
                mark = "!" if t["bounty"] else " "
                log.info("TRIAGE%s %s | %s | bounty=%s | %s",
                         mark, cid, t["severity"],
                         "SIM" if t["bounty"] else "nao", t["reason"])
                if t["bounty"]:
                    state["opportunities"].append({
                        "ts": int(time.time()), "source": "cve",
                        "asset": cid, "rsi": None,
                        "note": "triage " + t["severity"] + ": " + t["reason"],
                    })
        else:
            log.info("CVE %s | %s", cid, desc[:120])
    state["cve_triage"] = state["cve_triage"][-60:]

# ---------------- staking ----------------

def staking_report(state, config):
    try:
        infl = rpc_call("getInflationRate", [])
    except Exception as e:
        log.warning("inflation RPC falhou: %s", e)
        return
    total = float(infl.get("total", 0))
    est_apy = total * 0.8 * 0.95
    balance = state.get("last_balance", 0.0)
    reserve = config["min_reserve_sol"]
    threshold = config["staking_min_excess_sol"]
    excess = balance - reserve - threshold
    log.info("STAKING: inflacao anual %.2f%% | yield est. %.2f%% a.a.",
             total * 100, est_apy * 100)
    if excess > 0:
        log.info("STAKING: excesso de %.4f SOL acima da reserva - candidato a stake", excess)
        state["opportunities"].append({
            "ts": int(time.time()), "source": "staking",
            "asset": "SOL", "rsi": None,
            "note": "stakear %.4f SOL (renda passiva on-chain)" % excess,
        })
    else:
        log.info("STAKING: saldo abaixo do minimo para stakear (falta %.4f SOL)", -excess)

# ---------------- salario trading ----------------

def trading_salary(state, config):
    path = config.get("trading_state_path", "")
    if not path or not os.path.exists(path):
        return
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log.warning("salario trading: leitura falhou: %s", e)
        return
    cash = float(data.get("cash", 0.0))
    last = state.get("last_trading_cash")
    if last is not None and cash > last:
        gain = cash - last
        state["lifetime_earned"] += gain
        log.info("SALARIO trading: +%.4f USDT de lucro do bot", gain)
    state["last_trading_cash"] = cash

# ---------------- politica de gastos ----------------

def spend_request(state, config, amount, reason):
    today = datetime.now().strftime("%Y-%m-%d")
    if state["spend_day"] != today:
        state["spend_day"] = today
        state["spent_today"] = 0.0
    balance = state.get("last_balance", 0.0)
    reserve = config["min_reserve_sol"]
    limit = config["daily_spend_limit_sol"]
    if amount <= 0:
        return False
    if balance - amount < reserve:
        log.warning("GASTO NEGADO (reserva): %s | %.6f SOL", reason, amount)
        return False
    if state["spent_today"] + amount > limit:
        log.warning("GASTO NEGADO (limite diario): %s | %.6f SOL", reason, amount)
        return False
    state["spent_today"] += amount
    log.info("GASTO APROVADO: %s | %.6f SOL | hoje: %.6f", reason, amount, state["spent_today"])
    return True

# ---------------- nucleo ----------------

def survival_report(state):
    earned = state["lifetime_earned"]
    spent = state["lifetime_spent"]
    ops = len(state["opportunities"])
    balance = state.get("last_balance", 0.0)
    score = earned - spent
    if balance < 0.002:
        status = "MORRENDO (sem gas)"
    elif score >= 0:
        status = "VIVAL e LUCRANDO"
    else:
        status = "VIVAL (consumindo reserva)"
    log.info("SENTRIC %s | saldo=%.4f SOL | ganho=%.4f | gasto=%.4f | oportunidades=%d | cves=%d",
             status, balance, earned, spent, ops, state["cves_seen"])

def run(interval):
    config = load_config()
    sk, address = load_or_create_keypair()
    state = load_state()
    state["address"] = address
    save_state(state)
    write_identity(address)
    log.info("=" * 56)
    log.info("%s v%s | %s", NAME, VERSION, address)
    log.info("modulos: %s", ", ".join(k for k, v in config["modules"].items() if v))
    log.info("pare com: touch %s", STOP_FILE)
    log.info("=" * 56)
    last_balance = None
    while True:
        if os.path.exists(STOP_FILE):
            log.warning("STOP detectado - desligando")
            break
        state["cycles"] += 1
        if config["modules"].get("treasury", True):
            try:
                balance = get_balance(address)
            except Exception as e:
                log.warning("RPC falhou: %s", e)
                balance = state.get("last_balance", 0.0)
            if last_balance is not None:
                delta = balance - last_balance
                if delta > 0:
                    state["lifetime_earned"] += delta
                    log.info("ENTRADA: +%.6f SOL", delta)
                elif delta < 0:
                    state["lifetime_spent"] += -delta
                    log.info("SAIDA: -%.6f SOL", -delta)
            last_balance = balance
            state["last_balance"] = balance
            state["heartbeats"] += 1
            state["balance_history"].append([int(time.time()), round(balance, 6)])
            state["balance_history"] = state["balance_history"][-500:]
            try:
                usdt = get_token_balance(address, USDT_MINT)
            except Exception as e:
                usdt = state.get("last_usdt", 0.0)
            state["last_usdt"] = usdt
            if usdt > 0:
                log.info("TESOURARIA: %.2f USDT detectados na carteira", usdt)
            survival_report(state)
        if config["modules"].get("trading_salary", True):
            trading_salary(state, config)
        due_markets = (config["modules"].get("markets", True) and
                       state["cycles"] % config["scan_markets_every_cycles"] == 0)
        if due_markets:
            scan_markets(state)
        due_cve = (config["modules"].get("cve_recon", True) and
                   state["cycles"] % config["scan_cve_every_cycles"] == 0)
        if due_cve:
            scan_cves(state, config)
        due_staking = (config["modules"].get("staking", True) and
                       state["cycles"] % config["scan_markets_every_cycles"] == 0)
        if due_staking:
            staking_report(state, config)
        save_state(state)
        time.sleep(interval)

def main():
    ap = argparse.ArgumentParser(description="SENTRIC - agente autonomo v0.3")
    ap.add_argument("--init", action="store_true")
    ap.add_argument("--interval", type=int, default=60)
    args = ap.parse_args()
    os.makedirs(DATA_DIR, exist_ok=True)
    if args.init:
        load_config()
        sk, address = load_or_create_keypair()
        state = load_state()
        state["address"] = address
        save_state(state)
        write_identity(address)
        print("SENTRIC v" + VERSION + " criado.")
        print("endereco:", address)
        print("pasta:  ", DATA_DIR)
        return
    run(args.interval)

if __name__ == "__main__":
    main()
