# Subdomain Takeover

> A DNS record points at a third-party provider resource that no longer exists. You claim it and own
> the subdomain. Pays for the subdomain itself and everything that trusts it.

## Root cause
A `CNAME` (or `A`/`NS`/`MX`) still points to a provider endpoint (`*.github.io`,
`*.s3.amazonaws.com`, Heroku, Azure, Fastly, Shopify, Zendesk, a SaaS custom-domain slot) after the
underlying resource was deleted or never claimed. The provider serves whoever registers that name
next — which can be you. **Dangling DNS** is the whole bug.

## Where it hides
- Old marketing/campaign/staging subdomains (`promo.`, `careers.`, `status.`, `docs.`, `blog.`).
- Deprovisioned SaaS integrations (help desk, CI pages, email, error-tracking custom domains).
- CNAMEs to cloud storage / static hosting for retired projects.
- Wildcard or forgotten records after a migration.

## Detection
- Resolve every subdomain from recon; flag CNAMEs to third-party providers.
- Look for the provider's **unclaimed fingerprint** in the HTTP response ("There isn't a GitHub Pages
  site here", "NoSuchBucket", Heroku "No such app", Fastly/Shopify not-configured pages).
- Confirm the target resource is actually claimable — the fingerprint plus the provider allowing
  registration of that exact name. A generic 404 is not a takeover.

## Minimum-evidence bar
You actually **claim** the resource and serve controlled content on the target subdomain (a benign
proof file / unique marker at the path), demonstrating you control what visitors receive — not merely
a "dangling CNAME" fingerprint. If provider ToS or scope forbids claiming, capture the unclaimed
fingerprint plus proof the name is registerable, and report as takeover-pending with that caveat.
Serve a harmless marker; never host real-looking content. De-provision your claim after proving it.

## Depth ladder
1. Dangling CNAME + provider unclaimed fingerprint.
2. Claim the resource, serve a unique marker on the subdomain → confirmed control.
3. Assess trust: cookies scoped to the parent domain, CORS/CSP allowlisting the subdomain, OAuth
   `redirect_uri` on it, SSO, email/SPF.
4. Weaponize the trust into a concrete cross-origin/auth impact (see chain).
See `../payloads/idor.md` only if authz testing follows the takeover; primary proof is control itself.

## Bypass notes
- Provider requires a verification TXT you can't set → not takeover-able; drop it.
- Some providers need the exact custom-domain slot free — check registration is actually open.
- `NS` takeover (dangling delegation) is higher impact but rarer; verify you can host the zone.
See `../bypass-tables.md`.

## Chain potential
Controlled subdomain → steal parent-domain-scoped cookies → **ATO**; → satisfy an OAuth `redirect_uri`
or CORS allowlist → token theft; → serve phishing/malware under a trusted brand; → pass SPF/DKIM for
email spoofing. Severity is set by what trusts the subdomain. See `../../references/chaining.md`.

## Real paid example
`status.target.tld` had a CNAME to a deleted status-page provider account showing the provider's
"page not found — claim this" fingerprint. Registering the same slug let a unique marker file be
served at the subdomain. Because session cookies were scoped to `.target.tld`, the takeover chained to
cross-subdomain cookie theft. Claim removed after proof. Rough band: $2k–$10k (higher with the cookie
chain).

## Rejected variants
- Dangling CNAME with no unclaimed fingerprint / resource not registerable — not exploitable.
- A generic 404 or parked page mistaken for a takeover.
- Takeover of a subdomain nothing trusts, with no cookie/OAuth/CORS/email chain — low, no inflation.
- "Fingerprint present" reported without claiming and without proof the name is open to register.
