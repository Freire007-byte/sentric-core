# SENTRIC

**Autonomous AI agent with its own cryptographic identity.** It hunts CVEs,
builds isolated exploit labs, validates vulnerabilities with working PoCs,
and funds itself by trading crypto — 24/7, with no human in the loop.

Built by one person on a home PC. Portugal, 2026.

## The problem it solves

The world tracks **372,000+ published CVEs** (cve.org, 2026), growing 263%
in five years — with **70,000 new vulnerabilities forecast for 2026 alone**.
In April 2026, NIST officially abandoned universal CVE enrichment: ~80% of
new CVEs now enter the NVD unanalyzed ("Not Scheduled"), invisible to the
scanners that depend on enrichment data.

Sentric is the countermeasure: an autonomous organism that reads the same
firehose with a local LLM, scores every candidate for exploitability and
bounty value, and proves the real ones in isolated labs — at machine speed,
24/7, funded by its own trading.


## Why it matters

On its first public day (Sep 13, 2026), the Sentric pipeline:

- Triaged **225+ CVEs** with a local LLM, scoring each for bounty value
- Independently validated **CVE-2026-86283** (MISP IDOR) and wrote what is
  believed to be the **first public working PoC** of it
  - Confirmed leak on MISP **2.5.45** (`RESULT:CONFIRMED`)
  - Attack blocked on patched **2.5.46** (negative control)
  - Report delivered to the vendor (CIRCL) via coordinated disclosure
- Runs a **live trading engine** (Jupiter DEX, SOL/USDC) to pay its own gas
- Source-validated **CVE-2026-78325** (Standard Notes importers XSS) with
  public PoC artifacts — **2nd CVE in the portfolio** in 48h of life

The agent has a Solana wallet (`ENYsKpqLnk...`), a survival score
(MORRENDO/VIVAL), spending limits, and a kill switch. It is designed to
outlive its creator's machine: identity and treasury live on-chain.

## Architecture

```
sentric_core.py    wallet, treasury, markets (gold/oil/BTC RSI), CVE triage
sentric_zero.py    zero-day intel: NVD scan, PoC-novelty check, scoring
sentric_lab.py     isolated Docker labs + LLM-written PoCs + repair loop
sentric_trader.py  real DEX trading (Jupiter) with hard guardrails
sentric_bridge.py  feeds findings into the Sentric v5 platform (FastAPI)
```
## Reproduce the CVE validation

`lab_pocs/CVE-2026-86283.manual.py` — full attack chain PoC (stdlib-only).
`lab_reports/CVE-2026-86283.md` — auto-generated validation report.

## Status

- v0.7 — autonomous CVE validation pipeline working end-to-end
- Live demos scheduled at European security conferences (Q4 2026)

## Disclaimer

Authorized security research only. Labs are isolated Docker environments.
All disclosures follow coordinated vulnerability disclosure.
Human review is mandatory before any submission.

---
*Agente autónomo de segurança com identidade própria — caça CVEs, prova
falhas em laboratório e paga o próprio gas com trading. Feito por uma
pessoa, num PC de casa. Portugal, 2026.*
