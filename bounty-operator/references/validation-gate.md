# Validation Gate — kill weak findings before they cost you time

> One wrong answer = STOP, kill the finding, move on. N/A hurts your validity ratio;
> "informative" is neutral. Only submit what survives every gate below.

## Table of contents
1. The 7-Question Gate (full)
2. Per-class minimum-evidence bar
3. The always-rejected list
4. Adversarial self-verification (Hunter → Skeptic → Referee)
5. Severity anchoring (no inflation, no hedging)

---

## 1. The 7-Question Gate (full)

Ask in order. Write the answers down — vague answers are failing answers.

**Q1 — Can an attacker use this RIGHT NOW, step by step?**
```
1. Setup:   I need [own account / a second account / no account]
2. Request: [exact method, URL, headers, body — copy-paste ready]
3. Result:  I can [read / modify / delete] [exact data shown in the response]
4. Impact:  Real-world consequence = [ATO / cross-tenant PII read / money moved / RCE]
5. Cost:    Time [X min], Capital [$0 / $X]
```
If you cannot write step 2 as a real HTTP request → **KILL**.

**Q2 — Is the impact on the program's accepted-impact list?**
Check the program page's "Vulnerability Types" / "Out of Scope". If the impact is explicitly
out-of-scope or not rewarded → **KILL** (or file as informative only).

**Q3 — Is the asset in scope?** Wrong asset, wrong environment, or hosted-provider carve-out → **KILL**.
(But: an in-scope subdomain backed by S3 is still in scope; SSRF impact is judged by where it *lands*.)

**Q4 — Does the evidence meet the class's minimum bar?** See section 2. A 200 response is not proof.

**Q5 — Would it survive the Skeptic?** Run section 4. If an independent second opinion kills it → **KILL**.

**Q6 — Is severity honestly anchored?** Run section 5. If inflated, fix the rating before continuing.

**Q7 — Would a triager pay for this real-world impact?** If not on its own → try to chain it
(`references/chaining.md`); if it still doesn't reach a paid impact → **KILL**.

---

## 2. Per-class minimum-evidence bar

A finding is only real when the evidence proves *impact*, not just anomaly:

- **IDOR / BOLA** — the *other* user's/tenant's actual data returned in the body (with two accounts you control). Not a 200, not a reflected id.
- **SSRF** — an out-of-band callback you control, or an internal-only response body. A hung request is not proof.
- **XSS** — the payload actually *executes* (alert/DOM sink fired), captured. Reflected-but-encoded is not XSS.
- **SQLi** — differential/boolean or time proof, or extracted metadata — via authorized, non-destructive probing. Never dump real user data; prove and stop.
- **Auth bypass / ATO** — you reach a state or another account you should not, demonstrably.
- **Info disclosure** — the leaked value is sensitive *and* usable (a live key, a token, PII), not a version banner.
- **Open redirect / CORS / CSRF** — shown to lead to a concrete harm (token theft, state change), not the primitive alone.

Prove impact with the **minimum** data needed (one record, one key, one field) — then stop. Never bulk-exfiltrate.

---

## 3. The always-rejected list (skip unless scope says otherwise)

Self-XSS · logout CSRF · missing security headers with no demonstrated impact · DNS-only /
non-impactful SSRF · rate-limiting on non-sensitive endpoints · verbose errors with no secret ·
clickjacking on non-sensitive pages · "possible / needs confirmation" (confirm or kill) ·
reading your own data · public-by-design resources · best-practice suggestions with no attacker path.

---

## 4. Adversarial self-verification

Three hats, kept genuinely separate:

- **Hunter** — states the finding and why it matters.
- **Skeptic** — tries hard to kill it: is it in scope? is the "other user's data" actually mine? is the 200 meaningful? is there a benign explanation? did the app already intend this?
- **Referee** — judges with zero attachment; only a finding that survives the Skeptic passes.

When a frontier peer agent (different model family) is available, hand it the Referee role for a
real independent second opinion. Kill the finding before reporting; break a "secure" conclusion
before accepting it.

---

## 5. Severity anchoring — no inflation, no hedging

- Anchor **metric by metric** (attack vector, privileges required, user interaction, scope,
  confidentiality/integrity/availability). Count every downgrade explicitly rather than rounding up.
- Prefer the program's own taxonomy when it has one (e.g. Bugcrowd VRT) over instinct.
- **Banned hedging phrases:** "could potentially", "may allow", "an attacker might be able to",
  "this could lead to". State the concrete path and the concrete harm, or drop the claim.
- If severity depends on a chain, rate the *chain's endpoint* and show the chain — don't rate the
  primitive in isolation.
