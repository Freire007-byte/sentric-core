#!/usr/bin/env python3
import socket
socket.setdefaulttimeout(15)
# sentric_trader.py - SENTRIC v0.4 - Motor de trading real (Jupiter DEX, Solana)
import argparse
import base64
import json
import logging
import os
import sys
import time
import urllib.request
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("trader")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
import sentric_core as core

DATA_DIR = os.path.expanduser("~/sentric-core")
KEY_FILE = os.path.join(DATA_DIR, "sentric_key.json")
STATE_FILE = os.path.join(DATA_DIR, "trader_state.json")
STOP_FILE = os.path.join(DATA_DIR, "STOP_TRADER")

SOL_MINT = "So11111111111111111111111111111111111111112"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
JUP_QUOTE = "https://quote-api.jup.ag/v6/quote"
JUP_SWAP = "https://quote-api.jup.ag/v6/swap"

RSI_BUY = 30.0
RSI_SELL = 70.0
INTERVAL = 3600
COOLDOWN_HOURS = 6
MAX_TRADES_PER_DAY = 2
RESERVE_SOL = 0.02
MIN_NOTIONAL_USD = 1.0

def load_solders_keypair():
    try:
        from solders.keypair import Keypair
    except ImportError:
        log.error("solders nao instalado. Rode: pip install solana solders")
        sys.exit(1)
    with open(KEY_FILE, encoding="utf-8") as f:
        seed = bytes.fromhex(json.load(f)["seed_hex"])
    kp = Keypair.from_seed(seed)
    addr = core.b58encode(bytes(kp.pubkey()))
    log.info("chave carregada | endereco: %s", addr)
    return kp, addr

def http_get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())

def http_post_json(url, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())

def fetch_sol_closes(limit=60):
    url = ("https://query1.finance.yahoo.com/v8/finance/chart/SOL-USD"
           "?interval=1d&range=6mo")
    data = http_get_json(url)
    quote = data["chart"]["result"][0]["indicators"]["quote"][0]
    closes = [c for c in quote["close"] if c is not None]
    return closes[-limit:]

def get_quote(input_mint, output_mint, amount_units):
    url = (JUP_QUOTE + "?inputMint=" + input_mint
           + "&outputMint=" + output_mint
           + "&amount=" + str(int(amount_units))
           + "&slippageBps=300")
    try:
        return http_get_json(url)
    except Exception as e:
        log.warning("quote falhou: %s", e)
        return None

def send_swap(quote, kp, addr):
    payload = {
        "quoteResponse": quote,
        "userPublicKey": addr,
        "wrapAndUnwrapSol": True,
    }
    try:
        data = http_post_json(JUP_SWAP, payload)
    except Exception as e:
        log.warning("swap falhou: %s", e)
        return None
    swap_b64 = data.get("swapTransaction")
    if not swap_b64:
        log.warning("swap sem transacao: %s", data)
        return None
    try:
        from solana.transaction import VersionedTransaction
    except ImportError:
        from solders.transaction import VersionedTransaction
    raw = base64.b64decode(swap_b64)
    tx = VersionedTransaction.from_bytes(raw)
    signed = VersionedTransaction(tx.message, [kp])
    signed_b64 = base64.b64encode(bytes(signed)).decode()
    result = core.rpc_call("sendTransaction", [
        signed_b64,
        {"encoding": "base64", "skipPreflight": False,
         "preflightCommitment": "processed", "maxRetries": 3},
    ])
    return result

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {
        "holding": "SOL",
        "last_trade_ts": 0,
        "trade_day": "",
        "trades_today": 0,
        "trades": [],
    }

def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_FILE)

def can_trade(state):
    today = datetime.now().strftime("%Y-%m-%d")
    if state["trade_day"] != today:
        state["trade_day"] = today
        state["trades_today"] = 0
    if state["trades_today"] >= MAX_TRADES_PER_DAY:
        log.info("limite diario de trades atingido (%d)", MAX_TRADES_PER_DAY)
        return False
    elapsed = time.time() - state.get("last_trade_ts", 0)
    if elapsed < COOLDOWN_HOURS * 3600:
        log.info("cooldown: faltam %.1f h", (COOLDOWN_HOURS * 3600 - elapsed) / 3600)
        return False
    return True

def decide(closes, state):
    rsi = core.compute_rsi(closes)
    price = closes[-1]
    log.info("SOL/USD: %.2f | RSI %.1f | segurando: %s", price, rsi, state["holding"])
    if state["holding"] == "SOL" and rsi >= RSI_SELL:
        return "SELL_SOL", rsi, price
    if state["holding"] == "USDC" and rsi <= RSI_BUY:
        return "BUY_SOL", rsi, price
    return "HOLD", rsi, price

def execute(side, kp, addr, state, price, dry):
    sol_balance = core.get_balance(addr)
    usdc_balance = 0.0
    try:
        usdc_balance = core.get_token_balance(addr, USDC_MINT)
    except Exception:
        pass
    log.info("balances: %.4f SOL | %.2f USDC", sol_balance, usdc_balance)
    if side == "SELL_SOL":
        amount_sol = sol_balance - RESERVE_SOL
        notional = amount_sol * price
        if notional < MIN_NOTIONAL_USD:
            log.warning("notional %.2f USD abaixo do minimo", notional)
            return False
        amount_units = int(amount_sol * 1e9)
        quote = get_quote(SOL_MINT, USDC_MINT, amount_units)
        if not quote:
            return False
        out = int(quote.get("outAmount", 0)) / 1e6
        log.info("VENDA: %.4f SOL -> %.2f USDC (est.)", amount_sol, out)
        if dry:
            log.info("[DRY] nao executado")
            return False
        sig = send_swap(quote, kp, addr)
        if not sig:
            return False
        state["holding"] = "USDC"
        what = "%.4f SOL->USDC" % amount_sol
    else:
        if usdc_balance * 1.0 < MIN_NOTIONAL_USD:
            log.warning("USDC insuficiente (%.2f)", usdc_balance)
            return False
        amount_units = int(usdc_balance * 1e6)
        quote = get_quote(USDC_MINT, SOL_MINT, amount_units)
        if not quote:
            return False
        out = int(quote.get("outAmount", 0)) / 1e9
        log.info("COMPRA: %.2f USDC -> %.4f SOL (est.)", usdc_balance, out)
        if dry:
            log.info("[DRY] nao executado")
            return False
        sig = send_swap(quote, kp, addr)
        if not sig:
            return False
        state["holding"] = "SOL"
        what = "%.2f USDC->SOL" % usdc_balance
    state["last_trade_ts"] = time.time()
    state["trades_today"] += 1
    state["trades"].append({
        "ts": int(time.time()), "side": side, "what": what,
        "rsi": None, "sig": sig,
    })
    state["trades"] = state["trades"][-100:]
    save_state(state)
    log.info("TRADE EXECUTADO: %s | tx: %s", what, sig)
    return True

def run(dry, interval):
    kp, addr = load_solders_keypair()
    state = load_state()
    log.info("=" * 56)
    log.info("SENTRIC TRADER v0.4 | %s | modo: %s", addr, "DRY" if dry else "LIVE")
    log.info("pare com: touch %s", STOP_FILE)
    log.info("=" * 56)
    while True:
        if os.path.exists(STOP_FILE):
            log.warning("STOP_TRADER detectado - encerrando")
            break
        try:
            closes = fetch_sol_closes()
        except Exception as e:
            log.warning("dados de preco falharam: %s", e)
            time.sleep(interval)
            continue
        side, rsi, price = decide(closes, state)
        if side != "HOLD" and can_trade(state):
            execute(side, kp, addr, state, price, dry)
        save_state(state)
        time.sleep(interval)

def main():
    ap = argparse.ArgumentParser(description="SENTRIC trader v0.4 - Jupiter DEX")
    ap.add_argument("--live", action="store_true",
                    help="executa trades reais (padrao: dry-run)")
    ap.add_argument("--interval", type=int, default=INTERVAL)
    args = ap.parse_args()
    run(dry=not args.live, interval=args.interval)

if __name__ == "__main__":
    main()
