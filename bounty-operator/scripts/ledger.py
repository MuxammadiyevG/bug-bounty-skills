#!/usr/bin/env python3
"""
ledger.py — the coverage ledger: never re-test, never skip, always resume.

A discipline/orchestration tool (no network, no attacks). It records what surface+class was tested,
the result, and — when dismissed — WHY, so a killed false positive is never chewed twice and a new
session can resume exactly where the last one stopped. Append-only JSONL, one folder per target.

Storage (created on first use):
    <base>/targets/<target>/ledger.jsonl      # one row per test
    (pair with findings.jsonl / loot.jsonl as described in coverage-and-memory.md)

Commands:
    # log a test (append a row)
    python3 ledger.py add   --target acme.com --surface "/api/v2/orders/{id}" --class BOLA \
        --hypothesis "tenant A reads tenant B order" --result confirmed --fid F-014
    # results: confirmed | killed | inconclusive   (killed/inconclusive should carry --why)
    python3 ledger.py add   --target acme.com --surface "/login" --class SQLi \
        --result killed --why "parameterized; boolean+time both negative"

    # has this surface+class already been tested? (dedup gate — run before testing)
    python3 ledger.py seen  --target acme.com --surface "/api/v2/orders/{id}" --class BOLA
        # prints matching rows; exit 0 if seen, 1 if never tested

    # what to do next this session (resume protocol)
    python3 ledger.py resume --target acme.com     # inconclusive + untested-surface hints + stats
    python3 ledger.py list   --target acme.com [--result confirmed]

Base dir defaults to the current directory; override with --base.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

RESULTS = ("confirmed", "killed", "inconclusive")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ledger_path(base, target):
    d = os.path.join(base, "targets", target)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "ledger.jsonl")


def read_rows(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"warn: skipping malformed ledger line: {line[:80]}", file=sys.stderr)
    return rows


def cmd_add(args):
    if args.result not in RESULTS:
        print(f"error: --result must be one of {RESULTS}", file=sys.stderr)
        sys.exit(2)
    if args.result in ("killed", "inconclusive") and not args.why:
        print("error: killed/inconclusive rows require --why (so it's never re-tested blindly)",
              file=sys.stderr)
        sys.exit(2)
    row = {
        "ts": now(), "surface": args.surface, "class": args.klass,
        "hypothesis": args.hypothesis or "", "result": args.result,
        "why_dismissed": args.why or None, "fid": args.fid or None,
    }
    path = ledger_path(args.base, args.target)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    print(f"logged: {args.result} {args.klass} @ {args.surface} -> {path}")


def _match(rows, surface, klass):
    return [r for r in rows if r.get("surface") == surface and r.get("class") == klass]


def cmd_seen(args):
    rows = read_rows(ledger_path(args.base, args.target))
    hits = _match(rows, args.surface, args.klass)
    if hits:
        print(f"SEEN ({len(hits)}): {args.klass} @ {args.surface}")
        for r in hits:
            extra = f" why={r['why_dismissed']}" if r.get("why_dismissed") else ""
            print(f"  {r['ts']}  {r['result']}{extra}")
        sys.exit(0)
    print(f"NEW: {args.klass} @ {args.surface} has not been tested")
    sys.exit(1)


def cmd_list(args):
    rows = read_rows(ledger_path(args.base, args.target))
    if args.result:
        rows = [r for r in rows if r.get("result") == args.result]
    for r in rows:
        fid = f" [{r['fid']}]" if r.get("fid") else ""
        print(f"{r['ts']}  {r['result']:12} {r['class']:14} {r['surface']}{fid}")
    print(f"-- {len(rows)} row(s)")


def cmd_resume(args):
    rows = read_rows(ledger_path(args.base, args.target))
    if not rows:
        print(f"No ledger yet for {args.target}. Start with passive recon (recon-playbook.md).")
        return
    by_res = {}
    for r in rows:
        by_res.setdefault(r.get("result", "?"), []).append(r)
    print(f"== Resume: {args.target} ==")
    print(f"tested rows: {len(rows)} | " +
          " | ".join(f"{k}:{len(v)}" for k, v in sorted(by_res.items())))
    inconclusive = by_res.get("inconclusive", [])
    if inconclusive:
        print("\n[1] Retry these INCONCLUSIVE with a sharper hypothesis:")
        for r in inconclusive:
            print(f"    - {r['class']} @ {r['surface']}  (was: {r.get('hypothesis','')})")
    unchained = [r for r in by_res.get("confirmed", []) if r.get("fid")]
    if unchained:
        print("\n[2] Run the chain filter on CONFIRMED findings (chaining.md):")
        for r in unchained:
            print(f"    - {r['fid']}: {r['class']} @ {r['surface']}")
    print("\n[3] Then expand recon for new surface (recon-playbook.md).")
    print("Reminder: never conclude 'secure' while ranked surface remains untested.")


def main():
    ap = argparse.ArgumentParser(description="Coverage ledger for authorized engagements.")
    ap.add_argument("--base", default=".", help="base dir (default: cwd)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="append a test row")
    a.add_argument("--target", required=True)
    a.add_argument("--surface", required=True)
    a.add_argument("--class", dest="klass", required=True)
    a.add_argument("--hypothesis")
    a.add_argument("--result", required=True, help="confirmed|killed|inconclusive")
    a.add_argument("--why", help="required for killed/inconclusive")
    a.add_argument("--fid", help="finding id, e.g. F-014")
    a.set_defaults(func=cmd_add)

    s = sub.add_parser("seen", help="dedup gate: was surface+class tested?")
    s.add_argument("--target", required=True)
    s.add_argument("--surface", required=True)
    s.add_argument("--class", dest="klass", required=True)
    s.set_defaults(func=cmd_seen)

    l = sub.add_parser("list", help="list rows")
    l.add_argument("--target", required=True)
    l.add_argument("--result", help="filter by result")
    l.set_defaults(func=cmd_list)

    r = sub.add_parser("resume", help="what to do next this session")
    r.add_argument("--target", required=True)
    r.set_defaults(func=cmd_resume)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
