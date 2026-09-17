#!/usr/bin/env python3
"""
recon_wrap.py — scope-gated orchestrator for common recon tools (discipline, not exploitation).

This is an orchestration/discipline tool, NOT an exploit tool. It chains external recon binaries in a
safe pipeline and — before ANY stage that sends network traffic to a host — filters every candidate
host through the engagement scope (reusing scope_check.py). Out-of-scope hosts are dropped with a
warning; if no scope file is supplied, active (traffic-sending) stages refuse to run (fail closed).
Authorized targets only. If a tool is not installed, its stage prints an install hint and is skipped
(the pipeline never crashes). Results land in one folder per target (never a scratch dir).

Pipeline (each stage wraps a binary if present, else skips):
    subfinder                 -> subdomain enumeration        (passive, zero-touch to target)
    httpx / dnsx              -> live-host probing            (ACTIVE — scope-gated)
    gau / waybackurls         -> historical URLs              (passive, third-party archives)
    nuclei                    -> tech/CVE template sweep       (ACTIVE — scope-gated)

Safety model:
  - The seed target must itself be in scope (checked up front when --scope is given).
  - Before each ACTIVE stage, every candidate host is classified via scope_check; OUT hosts dropped.
  - --scope missing + an active stage would run  -> refuse (exit 2, fail closed).
  - --dry-run prints the exact commands it WOULD run and touches no network.
  - --passive-only runs only the zero-touch stages (subfinder, url-history).

Usage:
    python3 recon_wrap.py --scope scope.txt example.com
    python3 recon_wrap.py --scope scope.txt --passive-only example.com
    python3 recon_wrap.py --dry-run --scope scope.txt example.com
    python3 recon_wrap.py --scope scope.txt --rate 5 --out targets/example.com/recon example.com

Exit codes: 0 = ok (pipeline completed or dry-run printed); 2 = usage / scope error (fail closed).
"""
import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Reuse the audited scope logic rather than reimplementing it (single source of truth).
sys.path.insert(0, str(Path(__file__).resolve().parent))
import scope_check  # noqa: E402


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def in_scope(host, includes, excludes):
    verdict, _rule = scope_check.classify(host, includes, excludes)
    return verdict == "IN"


def gate_hosts(hosts, includes, excludes):
    """Split hosts into (kept in-scope, dropped out-of-scope). Warns on every drop.

    With no scope loaded (includes empty) there is nothing to gate against — pass through. This is
    only ever reached without a scope in --dry-run or passive-only runs; active traffic-sending
    stages are refused up front when --scope is absent (fail closed).
    """
    if not includes:
        return list(hosts), []
    kept, dropped = [], []
    for h in hosts:
        host = scope_check.host_of(h)
        if host and in_scope(host, includes, excludes):
            kept.append(host)
        else:
            dropped.append(h)
            print(f"warn: dropping OUT-OF-SCOPE host: {h!r}", file=sys.stderr)
    return kept, dropped


def read_lines(path):
    if not path.exists():
        return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def write_lines(path, lines):
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def resolve_tool(candidates):
    """Return (name, path) for the first installed candidate binary, else (None, None)."""
    for name in candidates:
        path = shutil.which(name)
        if path:
            return name, path
    return None, None


INSTALL_HINTS = {
    "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "dnsx": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
}


def hint_for(candidates):
    for c in candidates:
        if c in INSTALL_HINTS:
            return f"{c}: {INSTALL_HINTS[c]}"
    return f"install one of: {', '.join(candidates)}"


def run(cmd, outfile=None, stdin_lines=None, dry_run=False):
    """Run a command. In dry-run, only print it. Returns rc (0 on dry-run/skip-friendly)."""
    printable = " ".join(cmd) + (f"  > {outfile}" if outfile else "")
    if dry_run:
        print(f"    WOULD RUN: {printable}")
        return 0
    print(f"    RUN: {printable}")
    stdin_data = ("\n".join(stdin_lines) + "\n") if stdin_lines else None
    try:
        proc = subprocess.run(
            cmd, input=stdin_data, capture_output=True, text=True, check=False,
        )
    except OSError as exc:
        print(f"    error: failed to launch {cmd[0]!r}: {exc}", file=sys.stderr)
        return 1
    if proc.stderr.strip():
        # tools are noisy on stderr; surface only a short tail
        tail = proc.stderr.strip().splitlines()[-1]
        print(f"    ({cmd[0]} stderr) {tail}", file=sys.stderr)
    if outfile is not None:
        # some tools self-write via -o; if they printed to stdout, capture that too
        existing = read_lines(outfile) if outfile.exists() else []
        stdout_lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        merged = sorted(set(existing) | set(stdout_lines))
        if merged:
            write_lines(outfile, merged)
    return proc.returncode


def stage_subfinder(target, outdir, rate, dry_run, summary):
    name, _ = resolve_tool(["subfinder"])
    out = outdir / "subfinder.txt"
    entry = {"stage": "subfinder", "type": "passive", "tool": name}
    if not name:
        print("  [subfinder] SKIP (not installed). Install hint:")
        print(f"      {hint_for(['subfinder'])}")
        entry["status"] = "skipped-missing"
        summary["stages"].append(entry)
        return out
    cmd = [name, "-d", target, "-silent", "-rl", str(rate), "-o", str(out)]
    print("  [subfinder] subdomain enumeration (passive)")
    run(cmd, outfile=out, dry_run=dry_run)
    entry["status"] = "dry-run" if dry_run else "ran"
    entry["output"] = str(out)
    summary["stages"].append(entry)
    return out


def stage_live(candidate_hosts, outdir, rate, dry_run, includes, excludes, summary):
    name, _ = resolve_tool(["httpx", "dnsx"])
    out = outdir / "live.txt"
    entry = {"stage": "live-hosts", "type": "active", "tool": name}
    if not name:
        print("  [live-hosts] SKIP (not installed). Install hint:")
        print(f"      {hint_for(['httpx', 'dnsx'])}")
        entry["status"] = "skipped-missing"
        summary["stages"].append(entry)
        return out
    kept, dropped = gate_hosts(candidate_hosts, includes, excludes)
    entry["candidates"] = len(candidate_hosts)
    entry["in_scope"] = len(kept)
    entry["dropped_oos"] = len(dropped)
    if not kept:
        print("  [live-hosts] SKIP: no in-scope candidate hosts after scope gate")
        entry["status"] = "skipped-empty"
        summary["stages"].append(entry)
        return out
    hosts_file = outdir / "_live_input.txt"
    if not dry_run:
        write_lines(hosts_file, kept)
    print(f"  [live-hosts] probing {len(kept)} in-scope host(s) via {name} (ACTIVE, rl={rate})")
    if name == "httpx":
        cmd = [name, "-l", str(hosts_file), "-silent", "-rl", str(rate), "-o", str(out)]
    else:  # dnsx
        cmd = [name, "-l", str(hosts_file), "-silent", "-rl", str(rate), "-o", str(out)]
    if dry_run:
        print(f"      (in-scope input would be: {', '.join(kept)})")
    run(cmd, outfile=out, dry_run=dry_run)
    entry["status"] = "dry-run" if dry_run else "ran"
    entry["output"] = str(out)
    summary["stages"].append(entry)
    return out


def stage_urls(hosts, outdir, dry_run, includes, excludes, summary):
    name, _ = resolve_tool(["gau", "waybackurls"])
    out = outdir / "urls.txt"
    entry = {"stage": "url-history", "type": "passive", "tool": name}
    if not name:
        print("  [url-history] SKIP (not installed). Install hint:")
        print(f"      {hint_for(['gau', 'waybackurls'])}")
        entry["status"] = "skipped-missing"
        summary["stages"].append(entry)
        return out
    # Passive (third-party archives), but only feed in-scope hosts as a discipline.
    kept, _dropped = gate_hosts(hosts, includes, excludes)
    if not kept:
        print("  [url-history] SKIP: no in-scope hosts to query")
        entry["status"] = "skipped-empty"
        summary["stages"].append(entry)
        return out
    print(f"  [url-history] collecting historical URLs for {len(kept)} host(s) via {name} (passive)")
    if name == "gau":
        cmd = [name, "--threads", "2"]
    else:  # waybackurls reads hosts on stdin
        cmd = [name]
    if dry_run:
        print(f"      WOULD RUN: (echo hosts) | {' '.join(cmd)}  > {out}")
        print(f"      (hosts: {', '.join(kept)})")
    else:
        run(cmd, outfile=out, stdin_lines=kept, dry_run=False)
    entry["status"] = "dry-run" if dry_run else "ran"
    entry["output"] = str(out)
    summary["stages"].append(entry)
    return out


def stage_nuclei(live_file, outdir, rate, dry_run, includes, excludes, summary):
    name, _ = resolve_tool(["nuclei"])
    out = outdir / "nuclei.txt"
    entry = {"stage": "nuclei", "type": "active", "tool": name}
    if not name:
        print("  [nuclei] SKIP (not installed). Install hint:")
        print(f"      {hint_for(['nuclei'])}")
        entry["status"] = "skipped-missing"
        summary["stages"].append(entry)
        return out
    live_hosts = read_lines(live_file)
    if dry_run and not live_hosts:
        live_hosts = ["<in-scope live hosts from previous stage>"]
    kept, dropped = ([], [])
    if live_hosts and not (len(live_hosts) == 1 and live_hosts[0].startswith("<")):
        kept, dropped = gate_hosts(live_hosts, includes, excludes)
    else:
        kept = live_hosts  # dry-run placeholder
    entry["candidates"] = len(live_hosts)
    entry["in_scope"] = len(kept)
    entry["dropped_oos"] = len(dropped)
    if not kept:
        print("  [nuclei] SKIP: no in-scope live hosts to scan")
        entry["status"] = "skipped-empty"
        summary["stages"].append(entry)
        return out
    targets_file = outdir / "_nuclei_input.txt"
    if not dry_run:
        write_lines(targets_file, kept)
    print(f"  [nuclei] tech/CVE template sweep on {len(kept)} in-scope host(s) (ACTIVE, rl={rate})")
    # Conservative: tech-targeted tags, capped rate + concurrency. Not a full-blast scan.
    cmd = [
        name, "-l", str(targets_file), "-silent",
        "-tags", "cve,tech,misconfig,exposure",
        "-rl", str(rate), "-c", "10", "-o", str(out),
    ]
    if dry_run:
        print(f"      (in-scope input would be: {', '.join(kept)})")
    run(cmd, outfile=out, dry_run=dry_run)
    entry["status"] = "dry-run" if dry_run else "ran"
    entry["output"] = str(out)
    summary["stages"].append(entry)
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Scope-gated recon orchestrator (authorized targets only).",
    )
    ap.add_argument("target", help="seed target domain (must be in scope)")
    ap.add_argument("--scope", help="path to scope file (required for active stages; fail closed)")
    ap.add_argument("--out", help="output dir (default: targets/<target>/recon)")
    ap.add_argument("--rate", type=int, default=10,
                    help="conservative rate-limit passed to tools (default: 10)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the exact commands that WOULD run; touch no network")
    ap.add_argument("--passive-only", action="store_true",
                    help="run only zero-touch stages (subfinder, url-history)")
    args = ap.parse_args()

    target = scope_check.host_of(args.target)
    if not target:
        print(f"error: invalid target {args.target!r}", file=sys.stderr)
        sys.exit(2)

    # An active stage is anything that sends traffic to the target's own hosts.
    active_stages_planned = not args.passive_only

    includes, excludes = [], []
    if args.scope:
        includes, excludes = scope_check.load_scope(args.scope)  # exits 2 on scope-file error
        if not in_scope(target, includes, excludes):
            print(f"error: seed target {target!r} is OUT OF SCOPE per {args.scope!r} (fail closed)",
                  file=sys.stderr)
            sys.exit(2)
    else:
        # Fail closed: no scope means no active traffic is permitted.
        if active_stages_planned and not args.dry_run:
            print("error: --scope is required for active stages (live-hosts, nuclei). "
                  "Re-run with --scope, or use --passive-only. (fail closed)", file=sys.stderr)
            sys.exit(2)
        if args.dry_run:
            print("note: --dry-run with no --scope; commands are printed but scope gating is a no-op",
                  file=sys.stderr)

    outdir = Path(args.out) if args.out else Path("targets") / target / "recon"
    if not args.dry_run:
        outdir.mkdir(parents=True, exist_ok=True)

    mode = "dry-run" if args.dry_run else ("passive-only" if args.passive_only else "full")
    print(f"== recon_wrap :: target={target} :: mode={mode} :: rate={args.rate} :: out={outdir} ==")

    summary = {
        "ts": now(), "target": target, "mode": mode, "rate": args.rate,
        "scope": args.scope, "output_dir": str(outdir), "stages": [],
    }

    # 1) subfinder (passive)
    subs_file = stage_subfinder(target, outdir, args.rate, args.dry_run, summary)
    sub_hosts = read_lines(subs_file)
    candidate_hosts = sorted(set(sub_hosts) | {target})

    live_file = outdir / "live.txt"
    if args.passive_only:
        print("  [live-hosts] SKIP (passive-only mode: zero-touch stages only)")
        summary["stages"].append({"stage": "live-hosts", "type": "active",
                                  "status": "skipped-mode"})
        url_input = candidate_hosts
    else:
        # 2) live hosts (ACTIVE, scope-gated)
        live_file = stage_live(candidate_hosts, outdir, args.rate, args.dry_run,
                               includes, excludes, summary)
        live_hosts = read_lines(live_file)
        url_input = live_hosts or candidate_hosts

    # 3) url history (passive)
    stage_urls(url_input, outdir, args.dry_run, includes, excludes, summary)

    # 4) nuclei (ACTIVE, scope-gated)
    if args.passive_only:
        print("  [nuclei] SKIP (passive-only mode: zero-touch stages only)")
        summary["stages"].append({"stage": "nuclei", "type": "active", "status": "skipped-mode"})
    else:
        stage_nuclei(live_file, outdir, args.rate, args.dry_run,
                     includes, excludes, summary)

    if args.dry_run:
        print("\n== dry-run complete: no network traffic sent ==")
        print(json.dumps(summary, indent=2))
    else:
        summary_path = outdir / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(f"\n== recon complete :: summary -> {summary_path} ==")
    sys.exit(0)


if __name__ == "__main__":
    main()
