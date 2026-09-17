# Insecure Deserialization

> Untrusted bytes rebuilt into objects, triggering gadget chains at load time. RCE-tier across PHP, Java, Python, and Node — the endpoint of many chains.

## Root cause
The app deserializes attacker-controlled data with a format that reconstructs typed objects and runs
lifecycle hooks (`__wakeup`/`__destruct`, `readObject`, `__reduce__`, `toObject`/`fromJSON` with
functions). An attacker supplies a serialized object whose fields drive existing library methods —
a **gadget chain** — to reach a dangerous sink (exec, file write, SQL, SSRF) without any app bug
beyond trusting the blob.

## Where it hides
- **PHP:** `unserialize()` on cookies/params; `phar://` wrappers reached by *any* filesystem op on an
  attacker-named path (LFI/upload → phar POP chain). Magic-method gadgets in the framework.
- **Java:** endpoints reading `ObjectInputStream` — RMI, JMX, T3, custom binary APIs, JSF ViewState,
  Java-serialized cookies/tokens. Magic bytes `AC ED 00 05` (base64 `rO0`).
- **Python:** `pickle.loads` on cookies/cache/queues; PyYAML `yaml.load` without SafeLoader; signed
  cookies with a leaked/weak secret (forge then deserialize).
- **Node:** `node-serialize`/`serialize-javascript` round-trips that execute embedded functions;
  `_$$ND_FUNC$$_` IIFE trick.

## Detection
- Fingerprint the format: base64 starting `rO0` (Java), `Tzo` (PHP `O:`), pickle opcodes, YAML tags.
- Send a benign gadget that triggers an **out-of-band** callback (DNS/HTTP) — the clean proof for
  blind sinks. URLDNS-style DNS lookup for Java; a callback gadget for others.
- Flip one byte / change class length prefix and watch for type/parse errors confirming live deser.

## Minimum-evidence bar
Code execution or an out-of-band callback the server made from your gadget — not merely "it accepts
a serialized blob" or a deserialization error. For blind chains, the OOB hit carrying server-side
data is the bar. Demonstrate with one harmless gadget (DNS lookup / `id`), then stop.

## Depth ladder
1. Confirm live deserialization (parse-error differential / format match).
2. OOB gadget (URLDNS / callback) → proves reach without RCE risk.
3. Full chain to RCE via the present library gadgets (ysoserial payload family for Java;
   handcrafted POP chain for PHP; `__reduce__` for pickle; `_$$ND_FUNC$$_` for Node).
4. **phar://** — trigger PHP deser through a filesystem sink when `unserialize` isn't directly exposed.
See `../payloads/xxe.md` only if the entry is XML-wrapped; otherwise use gadget references inline.

## Bypass notes
- Java allowlist/`ObjectInputFilter` → find a gadget the filter misses, or a non-Java entry (JSON
  polymorphic typing: Jackson `@class`, `enableDefaultTyping`).
- PHP `__wakeup` guard → CVE-style property-count bypass; or route through `phar://` to skip it.
- Signed Python cookie → recover/guess the secret, re-sign a pickle. See `../bypass-tables.md`.

## Chain potential
LFI/upload → `phar://` → PHP POP RCE. Leaked secret (JS bundle) → forge signed pickle → RCE. Deser
RCE → env/cloud creds → infra. See `../../references/chaining.md`.

## Real paid example
An internal-looking API returned a base64 `rO0…` session token. A URLDNS gadget produced a DNS lookup
from the app server, confirming blind Java deserialization; a CommonsCollections gadget then ran `id`
out-of-band. RCE proven with a harmless command. Rough band: $10k–$30k.

## Rejected variants
- App accepts a serialized blob but uses a safe loader (`SafeLoader`, `JSON.parse`, allowlist) — no
  gadget fires. Not a bug.
- A deserialization *error* in a stack trace with no reachable sink — info leak at most.
- Node `JSON.parse` reported as "deserialization RCE" — no function execution, no chain.
- Local-only pickle you control both ends of.
