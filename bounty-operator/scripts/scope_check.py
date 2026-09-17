#!/usr/bin/env python3
"""
scope_check.py — decide whether a host/URL is IN or OUT of an engagement's scope.

This is a safety/discipline tool, not an attack tool. It performs no network activity: it only
compares candidate hosts against an operator-provided scope file so the agent never sends a request
to an out-of-scope asset (Rule 0 / Rule 1).

Scope file format (plain text, one rule per line; '#' starts a comment):
    # in-scope rules have no prefix; out-of-scope rules start with '!'
    *.example.com
    api.example.com
    !blog.example.com          # explicit out-of-scope carve-out
    !*.internal.example.com

Matching rules:
  - A bare domain matches that exact host.
  - A leading '*.' wildcard matches any subdomain (any depth) AND the apex.
  - '!' marks an exclusion; exclusions ALWAYS win over inclusions (deny-overrides).
  - No matching include  -> OUT (fail closed).

Usage:
    python3 scope_check.py --scope scope.txt api.example.com https://x.example.com/path
    cat hosts.txt | python3 scope_check.py --scope scope.txt        # one host/URL per line
    python3 scope_check.py --scope scope.txt --quiet api.example.com # exit code only

Exit codes: 0 = all inputs in scope; 1 = at least one out of scope; 2 = usage/scope-file error.
"""
import argparse
import sys
from urllib.parse import urlparse


def load_scope(path):
    includes, excludes = [], []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.split("#", 1)[0].strip().lower()
                if not line:
                    continue
                if line.startswith("!"):
                    excludes.append(line[1:].strip())
                else:
                    includes.append(line)
    except OSError as exc:
        print(f"error: cannot read scope file {path!r}: {exc}", file=sys.stderr)
        sys.exit(2)
    if not includes:
        print(f"error: scope file {path!r} has no in-scope rules", file=sys.stderr)
        sys.exit(2)
    return includes, excludes


def host_of(candidate):
    """Extract a bare hostname from a URL or bare host. Returns lowercase host or ''."""
    c = candidate.strip().lower()
    if not c:
        return ""
    if "://" not in c:
        c = "//" + c  # let urlparse treat it as netloc
    netloc = urlparse(c).netloc or urlparse(c).path
    host = netloc.split("@")[-1].split(":")[0].strip("/")
    return host


def rule_matches(host, rule):
    if rule.startswith("*."):
        base = rule[2:]
        return host == base or host.endswith("." + base)
    return host == rule


def classify(host, includes, excludes):
    if not host:
        return "INVALID", None
    for r in excludes:                      # deny-overrides
        if rule_matches(host, r):
            return "OUT", f"!{r}"
    for r in includes:
        if rule_matches(host, r):
            return "IN", r
    return "OUT", "no-include-match(fail-closed)"


def main():
    ap = argparse.ArgumentParser(description="Check host/URL against an engagement scope file.")
    ap.add_argument("--scope", required=True, help="path to scope file")
    ap.add_argument("--quiet", action="store_true", help="no output, exit code only")
    ap.add_argument("targets", nargs="*", help="hosts/URLs; if omitted, read stdin")
    args = ap.parse_args()

    includes, excludes = load_scope(args.scope)

    targets = args.targets or [ln for ln in sys.stdin.read().splitlines() if ln.strip()]
    if not targets:
        print("error: no targets given (args or stdin)", file=sys.stderr)
        sys.exit(2)

    any_out = False
    for t in targets:
        host = host_of(t)
        verdict, rule = classify(host, includes, excludes)
        if verdict != "IN":
            any_out = True
        if not args.quiet:
            print(f"{verdict:7} {t}\t(host={host or '?'}; rule={rule})")
    sys.exit(0 if not any_out else 1)


if __name__ == "__main__":
    main()
