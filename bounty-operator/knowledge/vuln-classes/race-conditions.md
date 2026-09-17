# Race Conditions / TOCTOU

> The gap between "check" and "use" is a window. Fire N requests into it and the limit that should hold once holds zero times — double-spend, limit-overrun, duplicate grants.

## Root cause
The check and the state change aren't atomic. Between `SELECT balance` and `UPDATE balance`, or between `is coupon used?` and `mark used`, concurrent requests all pass the check before any commits. The gap: the developer reasoned about one request at a time; the database/lock doesn't serialize where they assumed.

## Where it hides
- Money/credits: withdrawal, transfer, gift-card redeem, wallet top-up, refund, cashout.
- One-time actions: single-use coupon, referral bonus, vote/like, invite acceptance, "claim reward".
- Limits/quotas: rate limits, seat counts, inventory/stock, follow limits, API-key creation.
- State transitions with a uniqueness assumption: apply once, redeem once, upgrade once.
- File TOCTOU: validate-then-move upload, symlink windows.

## Detection
- Capture the target request. Fire many copies *simultaneously* — Burp Repeater "send group in parallel" (single-packet attack over HTTP/2), Turbo Intruder `race-single-packet`, or a tight parallel script.
- Compare intended outcome (1 success) vs observed (N successes / balance > expected).
- Look for endpoints where success is idempotent-by-assumption but not idempotency-keyed.
- Single-packet attack neutralizes network jitter — use it for tight windows.

## Minimum-evidence bar
A **quantified overrun**: the action succeeded more times than allowed and the *state reflects it* — balance credited twice, coupon redeemed 5×, 3 seats on a 1-seat plan. Mirror `../../references/validation-gate.md`: two 200s isn't proof; the persisted state (balance, count, inventory) must show the invariant broke. Prove the minimum overrun (2×) on your own account, then stop.

## Depth ladder
1. Baseline: confirm the single-request limit (1 redemption, 1 withdrawal).
2. Parallel burst (single-packet / Turbo Intruder) → observe >1 success.
3. Confirm persisted impact: re-read balance/count/inventory.
4. Tune concurrency/timing; find the reliable window size.
5. Limit-overrun → double-spend: withdraw/transfer beyond balance.
6. Multi-endpoint TOCTOU: race a "check" endpoint against a "commit" endpoint.
7. Chain the overrun into financial or quota abuse (see business-logic.md).

## Bypass notes
- Per-account lock but not per-resource → race the shared resource.
- Idempotency key enforced → vary the key per request, or race before the key is registered.
- HTTP/1.1 jitter kills tight windows → use HTTP/2 single-packet.
- Server-side lock on one path → find the sibling path that mutates the same state without the lock.

## Chain potential
Race → double-spend → direct financial. Race a coupon/referral → free credit → real loss. Race seat/role grants → priv-esc. Race + logic flaw compounds the multiplier. See `../../references/chaining.md`.

## Real paid example
Gift-card redemption checked balance then debited in a separate statement. 20 parallel single-packet redeems of a $50 card credited the wallet ~$950 before the balance zeroed. Reproduced to 2× first, then quantified. Band: **$2k–$8k** (direct financial, clean repro).

## Rejected variants
- Two concurrent 200s where the final state is still correct (server serialized properly).
- "Rate limit can be exceeded" on a non-sensitive endpoint with no impact.
- Duplicate submit the server dedupes via idempotency.
- Overrun you can't tie to a state change (no balance/count/inventory delta shown).
