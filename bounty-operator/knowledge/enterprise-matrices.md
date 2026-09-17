# Enterprise Attack Matrices

Attack surface maps for the identity and edge platforms that gate most enterprise estates. **Defensive-testing framing, authorized engagements only** — these are the paths a red-teamer validates and a blue-teamer hardens. Prove the misconfig with one benign check, document it, stop. No credential harvesting from real users, no lateral movement beyond proof.

---

## Microsoft 365 / Entra ID (Azure AD)

**Recon tells**
- `login.microsoftonline.com` redirect on the SSO; `autodiscover.<domain>`, `*.onmicrosoft.com` tenant.
- `GET /.well-known/openid-configuration` and `getuserrealm.srf?login=user@domain` reveal tenant id, federation (Managed vs Federated), and namespace.
- OneDrive/SharePoint URLs (`<tenant>-my.sharepoint.com`) confirm tenant name.

**Common misconfigs**
- Legacy auth (IMAP/POP/SMTP basic auth, EWS) still enabled → bypasses Conditional Access/MFA.
- Security defaults off with no CA policy; guest access unrestricted; user consent to third-party apps allowed.
- Over-permissioned app registrations / service principals with `Mail.ReadWrite`, `Directory.ReadWrite.All`.
- Device-code flow phishable; no CA on "all cloud apps".

**Auth attack paths (validate, don't exploit users)**
- User enumeration via `getuserrealm`/`GetCredentialType` (valid vs invalid response differ) → confirm the leak, don't spray real accounts.
- Password spray against legacy endpoints where MFA is skipped — only with explicit authorization and lockout-safe cadence.
- Consent-grant path: a malicious OAuth app requesting scopes; tell = tenant allows user consent.
- Token: primary-refresh-token / device-code abuse on unmanaged endpoints.

**High-value post-auth (prove access, then stop)**
- Enumerate directory with read-only Graph (`/me`, `/organization`) to prove token validity — no bulk user export.
- Confirm a role/app assignment exists; do not add Global Admin or modify CA.

---

## Okta

**Recon tells**
- `<tenant>.okta.com` / custom domain with Okta `x-okta-*` headers; `/.well-known/okta-organization`.
- `/api/v1/authn` and `/oauth2/default/.well-known/openid-configuration` exposed.
- Custom login widget reveals org id, factor types.

**Common misconfigs**
- Self-service registration / password reset enabled to the open internet.
- Weak or optional MFA factor policy; SMS/email OTP allowed as sole factor.
- Overly broad API tokens; `/api/v1` admin token in a client-side app.
- Open redirect in `fromURI`/`RelayState` → SSO response theft.

**Auth attack paths**
- Username enumeration via `/api/v1/authn` response differences → confirm, don't spray.
- Factor downgrade: choose the weakest allowed factor in the `authn` state machine.
- `fromURI` open redirect chained to steal the OIDC `code`.
- Session token (`sessionToken`) replay if it leaks in URLs/logs.

**High-value post-auth**
- Prove SSO into a downstream app once; do not pivot across the app catalog.
- Confirm an over-scoped API token works with one read call, then stop.

---

## VMware vCenter

**Recon tells**
- Port 443 with `/ui/`, `/sdk`, `/websso/`; `VMware vSphere` login title; `vsphere-client` cookies.
- `Server:` banner and build number → map to known CVE ranges (patch level).
- Exposed `/analytics/telemetry`, `/ui/vropspluginui/...` (SAML/plugin endpoints historically abused).

**Common misconfigs**
- Internet-exposed management plane (should be segmented).
- Unpatched build with known pre-auth RCE / SSRF / file-upload CVEs.
- Default/weak SSO admin (`administrator@vsphere.local`); no MFA on SSO.
- Verbose error pages leaking internal hostnames/paths.

**Auth attack paths**
- Version-match a known pre-auth CVE — validate reachability of the vulnerable endpoint with a benign probe, do not detonate a working RCE against production.
- SAML/SSO flaws (signature handling) on `/websso/`.
- Weak-credential login to SSO where authorized.

**High-value post-auth**
- Confirm access to inventory read (list one host/VM) to prove foothold; do not deploy, power-cycle, or snapshot.

---

## SSL-VPN edges (Fortinet / Pulse / Citrix)

**Recon tells**
- **Fortinet FortiGate/FortiOS:** `/remote/login`, `/remote/fgt_lang`, `Server: xxxxxxxx-xxxxx`, port 10443/443; favicon hash.
- **Pulse/Ivanti Connect Secure:** `/dana-na/auth/url_default/welcome.cgi`, `DSSignInURL` cookies, `/dana-cached/`.
- **Citrix ADC/NetScaler Gateway:** `/vpn/index.html`, `/cgi/`, `NSC_` cookies, `Citrix Gateway` login, `/nf/auth/`.

**Common misconfigs**
- Unpatched appliance matching a known pre-auth CVE (these edges are the most-exploited class in the wild).
- Management interface exposed to the internet; default admin; no MFA on the portal.
- Verbose version disclosure in login page / headers → precise CVE mapping.
- Weak lockout enabling spray.

**Auth attack paths**
- Fingerprint exact build → check against known pre-auth path-traversal / auth-bypass / RCE signatures; **validate the endpoint responds as vulnerable with a read-only proof (e.g. a benign file-read of a non-sensitive file, or version leak), never a full exploit or session-hijack against real users**.
- Portal password spray only with authorization and lockout awareness.
- Session/cookie theft paths (traversal to read session files) — prove reachability, stop before harvesting live sessions.

**High-value post-auth**
- Prove the foothold: one benign command / config-version read. Do not pull the full config, credentials, or pivot into the internal network. Document reachability and hand off.

---

## Cross-platform testing discipline
- Fingerprint precisely before touching anything — the exact build determines which CVE (if any) applies and keeps you from firing irrelevant exploits.
- On identity platforms, enumeration and factor-policy review reveal most findings without ever authenticating as a real user.
- For pre-auth RCE CVEs on appliances, a version-match plus a benign reachability probe is usually sufficient proof for a report — full exploitation risks the production system and other users. Get explicit sign-off before any live RCE.
- Minimum data, single proof, then stop and report.
