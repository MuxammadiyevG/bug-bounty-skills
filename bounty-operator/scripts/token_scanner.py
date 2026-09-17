#!/usr/bin/env python3
"""
token_scanner.py — heuristic rug / red-flag pass over token contract source.

This is a discipline/triage tool, NOT an exploit tool and NOT a verdict. It runs offline regex
heuristics over Solidity (EVM) and Rust/Anchor (Solana SPL) source and flags patterns that
correlate with rug pulls and honeypots. Every hit is a LEAD to confirm by hand — a match is not a
finding, and a clean scan is not a safe token. Authorized review / due-diligence use only.

Usage:
    python3 token_scanner.py <file_or_dir> [--chain evm|solana|auto] [--json]

Exit codes: 0 = ran (see report); 2 = usage / path error.

What it looks for (each = a lead, confirm manually):
  hidden-mint        mint()/_mint reachable by owner after deploy; no cap; obfuscated modifier
  honeypot           transfer/sell path gated by blacklist / max-tx / owner-only while buy works
  fee-manipulation   owner-settable fee with no hard cap (can be raised toward ~100%)
  authority-retained onlyOwner privileged setters; Solana freeze/mint authority not renounced
  fake-renounce      "renounce" that moves ownership to another controlled address / keeps a role
  lp-risk            owner withdraw path on liquidity / lock that is a no-op or short
  proxy-upgrade      upgradeable proxy — logic can be swapped after audit
"""
import argparse
import json
import os
import re
import sys

# (name, chain, compiled regex, why-it-matters) — heuristics, deliberately broad; expect false positives.
RULES = [
    ("hidden-mint", "evm", re.compile(r"function\s+\w*[mM]int\w*\s*\([^)]*\)[^{]*\bonlyOwner\b"),
     "owner can mint after deploy — dilution / infinite supply"),
    ("hidden-mint", "evm", re.compile(r"\b_mint\s*\(", re.I),
     "internal mint present — trace who can reach it and whether a cap exists"),
    ("honeypot", "evm", re.compile(r"(blacklist|_isBlacklisted|botList|maxTx|maxTransfer|canTransfer)", re.I),
     "transfer gating primitive — verify sell path is not owner-blockable"),
    ("honeypot", "evm", re.compile(r"require\s*\([^)]*(owner|_owner)[^)]*\)[^;]*;\s*//?[^\n]*transfer", re.I),
     "transfer guarded by owner check"),
    ("fee-manipulation", "evm", re.compile(r"function\s+set\w*(Fee|Tax)\w*\s*\(", re.I),
     "owner-settable fee/tax — check for a hard cap; uncapped = can approach 100%"),
    ("authority-retained", "evm", re.compile(r"\bonlyOwner\b"),
     "privileged owner functions — enumerate them; more surface = more rug levers"),
    ("fake-renounce", "evm", re.compile(r"function\s+renounce\w*\s*\([^)]*\)", re.I),
     "renounce present — confirm it zeroes ALL privileged roles, not just one"),
    ("lp-risk", "evm", re.compile(r"(removeLiquidity|withdraw\w*Liquidity|_lockTime|unlock\w*)", re.I),
     "liquidity withdraw/lock logic — verify lock is real and owner has no bypass"),
    ("proxy-upgrade", "evm", re.compile(r"(UUPSUpgradeable|TransparentUpgradeableProxy|delegatecall|_authorizeUpgrade)", re.I),
     "upgradeable — logic can change after review"),
    # Solana / Anchor
    ("authority-retained", "solana", re.compile(r"(freeze_authority|mint_authority)\s*[:=]", re.I),
     "freeze/mint authority set — if not None, owner can freeze accounts or mint"),
    ("authority-retained", "solana", re.compile(r"set_authority|SetAuthority", re.I),
     "authority change path — trace whether it is ever set to None"),
    ("honeypot", "solana", re.compile(r"(transfer_hook|permanent_delegate|TransferHook|PermanentDelegate)", re.I),
     "Token-2022 extension — transfer hook / permanent delegate can trap holders"),
    ("fake-renounce", "solana", re.compile(r"update_authority", re.I),
     "metadata update authority — mutable metadata / fake renounce risk"),
]

EVM_EXT = (".sol",)
SOL_EXT = (".rs",)


def detect_chain(path, files):
    exts = {os.path.splitext(f)[1].lower() for f in files}
    if exts & set(EVM_EXT) and not (exts & set(SOL_EXT)):
        return "evm"
    if exts & set(SOL_EXT) and not (exts & set(EVM_EXT)):
        return "solana"
    return "auto"


def gather(path):
    if os.path.isfile(path):
        return [path]
    out = []
    for dp, _, fs in os.walk(path):
        for f in fs:
            if f.lower().endswith(EVM_EXT + SOL_EXT):
                out.append(os.path.join(dp, f))
    return out


def scan(files, chain):
    hits = []
    for fp in files:
        try:
            src = open(fp, encoding="utf-8", errors="replace").read()
        except OSError as exc:
            print(f"warn: cannot read {fp}: {exc}", file=sys.stderr)
            continue
        lines = src.splitlines()
        for name, rchain, rx, why in RULES:
            if chain != "auto" and rchain != chain:
                continue
            for m in rx.finditer(src):
                ln = src.count("\n", 0, m.start()) + 1
                hits.append({
                    "flag": name, "chain": rchain, "file": fp, "line": ln,
                    "snippet": lines[ln - 1].strip()[:120] if ln - 1 < len(lines) else "",
                    "why": why,
                })
    return hits


def main():
    ap = argparse.ArgumentParser(description="Heuristic token rug/red-flag scanner (offline, leads not verdicts).")
    ap.add_argument("path", help="contract file or directory")
    ap.add_argument("--chain", choices=["evm", "solana", "auto"], default="auto")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path!r}", file=sys.stderr)
        sys.exit(2)

    files = gather(args.path)
    if not files:
        print("error: no .sol or .rs source found", file=sys.stderr)
        sys.exit(2)

    chain = args.chain if args.chain != "auto" else detect_chain(args.path, files)
    hits = scan(files, chain)

    if args.json:
        print(json.dumps({"chain": chain, "files": len(files), "hits": hits}, indent=2))
        return

    print(f"# token_scanner — {len(files)} file(s), chain={chain}")
    if not hits:
        print("no red-flag patterns matched. NOT a safety verdict — review authorities + logic by hand.")
        return
    by_flag = {}
    for h in hits:
        by_flag.setdefault(h["flag"], []).append(h)
    for flag in sorted(by_flag):
        print(f"\n## {flag}  ({len(by_flag[flag])} hit(s))")
        print(f"   why: {by_flag[flag][0]['why']}")
        for h in by_flag[flag][:20]:
            print(f"   {h['file']}:{h['line']}: {h['snippet']}")
    print("\nEach hit is a LEAD. Confirm by hand (who can call it, is there a cap, is authority truly None).")
    print("A clean scan does not mean the token is safe.")


if __name__ == "__main__":
    main()
