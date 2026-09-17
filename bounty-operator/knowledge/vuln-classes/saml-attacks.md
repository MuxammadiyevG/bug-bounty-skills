# SAML Attacks

> The SP trusts a signed assertion; you make it trust one you control. XML Signature Wrapping,
> comment injection, and signature stripping. Authentication bypass / cross-user login = ATO-tier.

## Root cause
SAML security rests on the SP verifying an XML digital signature over the assertion, then reading the
same assertion it verified. The bugs come from a gap between **what was verified** and **what is
consumed**:
- **XSW (XML Signature Wrapping):** the signature validates one element, but the SP processes a
  different injected element with attacker-controlled claims.
- **Comment injection:** an XML comment inside a `NameID` splits the value the parser returns
  (`admin<!---->@evil.tld` → the SP reads `admin`) while the signature over the raw bytes still checks.
- **Signature stripping / no-signature:** the SP accepts an unsigned assertion, a signature over the
  wrong scope (response vs assertion), or `SignatureMethod`/transform downgrades.

## Where it hides
- Any SAML SSO login (enterprise apps, admin consoles, SaaS tenant login).
- SP libraries with known parsing/canonicalization quirks; custom SAML handling.
- IdP-initiated flows and assertion consumer service (ACS) endpoints.

## Detection
- Capture the SAMLResponse (base64, often deflated) at the ACS endpoint.
- **XSW:** clone the signed assertion, inject a second assertion/element with a different `NameID`,
  reposition the `Signature` so the original still validates but the SP consumes the injected one.
  Test the standard XSW positions (wrap in Extensions, sibling, nested).
- **Comment injection:** insert `<!---->` into `NameID` to split the returned string; check whose
  identity the SP logs you in as.
- **Signature stripping:** remove the `Signature`, or change the referenced ID, and see if login still
  succeeds; test signed-response-but-unsigned-assertion and vice versa.

## Minimum-evidence bar
You authenticate as a **different user** (ideally a higher-privileged / another-tenant account you
don't control the IdP credentials for), shown by landing in that account — not a 200 on the ACS, not
"the assertion was accepted". Use a target account you're authorized to impersonate in testing
(your own second account). Prove one cross-user login, then stop.

## Depth ladder
1. Baseline: capture a valid signed assertion, confirm the SP enforces the signature.
2. Signature stripping / unsigned acceptance (cheapest).
3. Comment injection in `NameID` → identity confusion.
4. XSW positions → inject a fully attacker-chosen assertion while keeping a valid signature.
See `../payloads/xxe.md` for the XML primitives (entities, canonicalization) that support these.

## Bypass notes
- SP validates signature but re-parses with a different XML library → XSW/comment split lands.
- Strict schema → hide the injected assertion in an allowed element (Extensions).
- Deflated/base64 encoding is not security — re-encode after tampering. See `../bypass-tables.md`.

## Chain potential
Assertion forgery → log in as any user/admin → full **ATO** and, on multi-tenant SPs, cross-tenant
access. Combine with an email-based `NameID` and a known target address to pick the victim. See
`../../references/chaining.md`.

## Real paid example
Real disclosed reports:
- **SAML Authentication Bypass on uchat.uberinternal.com** (Uber, $8,500) — hackerone.com/reports/223014 — improper SAML verification bypassed OneLogin to reach internal chat.
- **SAML Signature verification bypass allows logging into any user (with specific conditions)** (GitHub, bounty undisclosed) — hackerone.com/reports/2579939 — ruby-saml parser differential (REXML vs Nokogiri) let a forged response log in as any user (CVE-2025-25291/25292).
- **HackerOne SAML signup domain enforcement bypass results in unauthorized access to HackerOne PullRequest organization** (HackerOne, bounty undisclosed) — hackerone.com/reports/2101076 — domain-enforcement gap in SAML signup grants org access.

**The recurring tell:** the SP verifies a signature over one thing but consumes another — the gap is a parser differential (two XML libraries disagree), a wrapping/injection, or a domain/claim enforcement miss. Payout tracks to a proven cross-user login, not "assertion accepted".

## Rejected variants
- Assertion tampering rejected — signature actually verified over the consumed element. Not a bug.
- Replaying your **own** valid assertion — no identity change, no privilege gained.
- Expired-assertion acceptance with no way to obtain a target's assertion — low, no cross-user impact.
- "SAML metadata is public" — by design, not a vulnerability.
