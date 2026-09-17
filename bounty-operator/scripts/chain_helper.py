#!/usr/bin/env python3
"""
chain_helper.py — suggest escalation chains for a confirmed finding (pure local logic, NO network).

This is a discipline/planning tool. Given a confirmed finding's class, it prints ranked candidate
escalation chains so a low/medium can be lifted to the tier that actually pays. Every ladder mirrors
`references/chaining.md`: single bugs get triaged, chains get paid, and severity is decided by where
the chain ENDS, not where it starts. It sends no traffic and touches no target — it only reasons over
an embedded table. The connector gadget is the creative part; this tool tells you what to hunt for.

Each chain is printed as:
    starting primitive  ->  connector gadget to look for  ->  end state    [SEVERITY]
ranked by payout impact (endpoint severity first).

Usage:
    python3 chain_helper.py idor            # ranked chains for the IDOR class
    python3 chain_helper.py open-redirect
    python3 chain_helper.py --list          # supported classes
    python3 chain_helper.py --all           # every ladder
    python3 chain_helper.py --filter        # the 10-question chain filter

Exit codes: 0 = ok; 2 = usage error (unknown class / bad args).
"""
import argparse
import sys

# Severity tiers, weighted for ranking (endpoint impact = payout).
TIER_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

# Escalation ladders keyed by finding class. Each chain: (primitive, connector, end_state, tier).
# Mirrors references/chaining.md; the connector is the gadget you go hunt for.
LADDERS = {
    "open-redirect": [
        ("open redirect", "OAuth/SSO redirect_uri that trusts the redirect (steal code/token)",
         "account takeover", "Critical"),
        ("open redirect", "server-side fetcher that follows the redirect (SSRF pivot)",
         "SSRF to internal/metadata", "High"),
        ("open redirect", "reset/verify link that embeds the token in the redirected URL",
         "token leak via Referer", "High"),
        ("open redirect", "login flow that reflects it back after auth",
         "credential phishing on trusted origin", "Medium"),
    ],
    "xss": [
        ("stored XSS", "runs in an admin/staff session or high-priv panel",
         "admin action / full account takeover", "Critical"),
        ("reflected/DOM XSS", "readable session cookie or CSRF token to exfiltrate",
         "session theft -> account takeover", "High"),
        ("XSS", "sensitive authenticated action reachable with the stolen CSRF token",
         "state change / privilege change", "High"),
        ("XSS", "login form to overlay or keylog",
         "credential capture", "Medium"),
    ],
    "ssrf": [
        ("SSRF", "cloud metadata endpoint (169.254.169.254) -> temp IAM credentials",
         "cloud API access / infra + data exposure", "Critical"),
        ("SSRF", "internal service with no auth (redis/elasticsearch/actuator/admin)",
         "internal data read or RCE", "Critical"),
        ("SSRF", "gopher:// or protocol smuggling to an internal TCP service",
         "unauth internal API call", "High"),
        ("blind SSRF", "OOB (DNS/HTTP) callback + internal port responses",
         "internal network mapping", "Medium"),
    ],
    "idor": [
        ("IDOR write", "same object id is writable across tenants",
         "cross-tenant modify / takeover", "Critical"),
        ("IDOR / BFLA", "privileged function callable without the role (vertical)",
         "privilege escalation", "Critical"),
        ("IDOR read", "predictable/enumerable ids over a PII or export endpoint",
         "mass PII read", "High"),
        ("sub-route auth skip", "child route (/orders/{id}/refund) skips the parent's check",
         "financial impact", "High"),
    ],
    "jwt": [
        ("JWT weakness", "alg:none / RS256->HS256 confusion / crackable HMAC secret",
         "forge admin claims -> privilege escalation", "Critical"),
        ("JWT weakness", "kid path traversal / jku|x5u pointing at attacker key",
         "sign arbitrary tokens -> account takeover", "Critical"),
        ("JWT weakness", "no exp / no revocation, token replays after logout",
         "session persistence", "Medium"),
    ],
    "cors": [
        ("CORS misconfig", "origin reflected with Allow-Credentials over a token/PII endpoint",
         "cross-origin token theft -> account takeover", "High"),
        ("CORS misconfig", "reflected origin over authenticated data responses",
         "cross-origin data theft", "High"),
        ("CORS misconfig", "null origin trusted, reachable from a sandboxed iframe",
         "authenticated response read", "Medium"),
    ],
    "file-upload": [
        ("file upload", "type/path filter bypass lands an executable in a served dir",
         "web shell -> RCE", "Critical"),
        ("file upload", "path traversal in filename overwrites config/cron/key",
         "RCE / config takeover", "Critical"),
        ("file upload", "SVG/HTML served same-origin and rendered",
         "stored XSS -> account takeover", "High"),
        ("file upload", "XML-based format (docx/xlsx/svg) parsed with external entities",
         "XXE -> SSRF / file read", "High"),
    ],
    "info-leak": [
        ("info leak", "JS bundle / response holds a live cloud key or admin token",
         "cloud or admin abuse", "Critical"),
        ("info leak", "exposed .git / source map reconstructs server source",
         "source read -> feeds next bug", "High"),
        ("info leak", "JS reveals internal endpoint or role/feature flag",
         "authz bypass / hidden surface", "High"),
        ("info leak", "verbose error / stack trace discloses stack + paths",
         "chain feeder for the next bug", "Low"),
    ],
    "smuggling": [
        ("request smuggling (CL.TE/TE.CL/H2.CL)", "shared front-end queue you can poison",
         "mass 0-click request/credential capture", "Critical"),
        ("request smuggling", "cache in front that stores the poisoned response",
         "cache poisoning -> stored XSS to all users", "Critical"),
        ("request smuggling", "front-end auth/WAF that the back-end trusts",
         "bypass to internal endpoints", "High"),
    ],
    "subdomain-takeover": [
        ("subdomain takeover", "taken-over host is an OAuth redirect / trusted callback domain",
         "steal auth codes -> account takeover", "Critical"),
        ("subdomain takeover", "parent sets cookies for *.domain (cookie scoping)",
         "session cookie theft", "High"),
        ("subdomain takeover", "dangling CNAME you can claim (S3/Pages/Heroku/etc.)",
         "malicious content on a trusted origin", "High"),
    ],
    "csrf": [
        ("CSRF", "email or password change endpoint lacks anti-CSRF",
         "account takeover", "High"),
        ("CSRF", "state-changing action + an XSS to defeat the token",
         "forced sensitive action", "High"),
        ("CSRF", "login form accepts cross-site POST (login CSRF)",
         "session fixation / victim in attacker account", "Medium"),
    ],
    "sqli": [
        ("SQL injection", "UNION/error path exposes the users or secrets table",
         "mass PII / credential dump", "Critical"),
        ("SQL injection", "stacked queries or file write primitive on the DB",
         "write / RCE", "Critical"),
        ("blind SQL injection", "OOB (DNS/HTTP) exfil channel",
         "data theft (blind)", "High"),
    ],
    "ssti": [
        ("SSTI", "template engine exposes an unsandboxed builtin / gadget",
         "RCE", "Critical"),
        ("SSTI", "engine allows file read (config/secret access)",
         "config/secret disclosure", "High"),
        ("blind SSTI", "arithmetic/OOB confirmation before payload delivery",
         "confirmed injection (pre-RCE)", "Medium"),
    ],
    "cache-poisoning": [
        ("cache poisoning", "unkeyed header reflected into a cached response",
         "stored XSS, mass 0-click", "Critical"),
        ("cache deception", "authenticated page cached under a static-looking path",
         "cross-user PII exposure", "High"),
    ],
    "auth": [
        ("auth flaw", "predictable/leaked password-reset token",
         "account takeover", "Critical"),
        ("auth flaw", "OAuth/SSO state or redirect abuse",
         "token theft -> account takeover", "Critical"),
        ("auth flaw", "MFA step skippable or brute-forceable",
         "MFA bypass -> auth bypass", "High"),
        ("auth flaw", "session fixation: pre-auth session id survives login",
         "session hijack", "High"),
    ],
}

# Class aliases -> canonical key, so common spellings resolve.
ALIASES = {
    "openredirect": "open-redirect", "redirect": "open-redirect", "open_redirect": "open-redirect",
    "cross-site-scripting": "xss",
    "bola": "idor", "bfla": "idor", "idor-bola": "idor",
    "json-web-token": "jwt", "jwt-none": "jwt",
    "upload": "file-upload", "file_upload": "file-upload",
    "leak": "info-leak", "infoleak": "info-leak", "information-disclosure": "info-leak",
    "info_leak": "info-leak", "disclosure": "info-leak",
    "request-smuggling": "smuggling", "http-smuggling": "smuggling", "desync": "smuggling",
    "takeover": "subdomain-takeover", "subtakeover": "subdomain-takeover",
    "sql": "sqli", "sql-injection": "sqli", "sqlinjection": "sqli",
    "cache": "cache-poisoning", "cache-deception": "cache-poisoning",
    "auth-bypass": "auth", "authentication": "auth", "ato": "auth",
}

CHAIN_FILTER = """The 10-question chain filter (run before spending >~30 min on any candidate):

  Q1.  Cross-user impact?            -> IDOR / BOLA family
  Q2.  Cross-tenant impact?          -> massive multiplier on SaaS
  Q3.  Leaks credentials / tokens?   -> secret family (esp. cloud / admin)
  Q4.  Pre-auth?                     -> removes the social-engineering step
  Q5.  0-click?                      -> removes the user-interaction cost
  Q6.  Persistent / stored?          -> keeps paying after the report
  Q7.  Reaches internal / metadata?  -> SSRF chain
  Q8.  Reads source / config?        -> feeds the next bug
  Q9.  Leads to RCE / SQLi / admin?  -> critical
  Q10. Mass-exploitable?             -> dramatic multiplier

  3+ YES  -> likely report-worthy on its own; still check whether a chain lifts the tier.
  1-2 YES -> keep escalating: find the connector gadget before you write it up.

The 30-minute rule: spend up to ~30 min per candidate finding a connector gadget. If the chain
reaches a paid impact, report the chain (describe the END STATE first). If not, log it in the
ledger with WHY it stalled and move on — return when a new primitive unlocks it."""


def normalize(name):
    key = name.strip().lower().replace(" ", "-").replace("_", "-")
    return ALIASES.get(key, key)


def rank(chains):
    # Highest endpoint severity first; preserve original order within a tier.
    return sorted(chains, key=lambda c: -TIER_WEIGHT.get(c[3], 0))


def print_ladder(klass):
    print(f"== escalation chains for: {klass} ==")
    for i, (prim, conn, end, tier) in enumerate(rank(LADDERS[klass]), 1):
        print(f"  {i}. [{tier}] {prim}")
        print(f"       -> connector: {conn}")
        print(f"       -> end state: {end}")
    print("  (severity is decided by where the chain ENDS; the connector is what you go hunt for.)")


def cmd_list():
    print("Supported finding classes:")
    for k in sorted(LADDERS):
        top = rank(LADDERS[k])[0]
        print(f"  {k:20} (best: {top[3]} -> {top[2]})")
    print("\nAliases also accepted, e.g. redirect, bola, upload, takeover, sql, ato.")


def cmd_all():
    for k in sorted(LADDERS):
        print_ladder(k)
        print()


def main():
    ap = argparse.ArgumentParser(
        description="Suggest ranked escalation chains for a confirmed finding class (local, no network).",
    )
    ap.add_argument("finding_class", nargs="?", help="finding class, e.g. idor, xss, ssrf")
    ap.add_argument("--list", action="store_true", help="list supported classes")
    ap.add_argument("--all", action="store_true", help="print every ladder")
    ap.add_argument("--filter", action="store_true", help="print the 10-question chain filter")
    args = ap.parse_args()

    if args.filter:
        print(CHAIN_FILTER)
        sys.exit(0)
    if args.list:
        cmd_list()
        sys.exit(0)
    if args.all:
        cmd_all()
        sys.exit(0)

    if not args.finding_class:
        ap.print_help()
        sys.exit(2)

    klass = normalize(args.finding_class)
    if klass not in LADDERS:
        print(f"error: unknown class {args.finding_class!r}", file=sys.stderr)
        print(f"supported: {', '.join(sorted(LADDERS))}", file=sys.stderr)
        print("use --list for details, or --all to see every ladder.", file=sys.stderr)
        sys.exit(2)

    print_ladder(klass)
    sys.exit(0)


if __name__ == "__main__":
    main()
