# Business-Logic / Sensitive-Flow Abuse

> No injection, no broken token — the feature works exactly as coded, and that's the bug. Scanners can't find it; triagers pay for it because it maps to money.

## Root cause
The implementation enforces the *happy path* but not the *invariant* behind it. The gap: the developer assumed the client would only send well-formed, in-order, in-range requests — so quantity can go negative, a discount can stack, a state can be reached out of sequence, or a price is trusted from the client.

## Where it hides
- Commerce: cart/checkout, coupon/promo stacking, price/quantity/currency in the request body, refund/cancel, gift-card/wallet top-up, shipping calc.
- Limits & quotas: trial extension, referral/bonus abuse, invite loops, plan/feature gating.
- Workflows/state machines: multi-step onboarding, approval chains, KYC, order status, subscription up/downgrade proration.
- Identity/tenancy: role assignment during invite, ownership transfer, seat counting.

## Detection
- Map the intended flow, then ask "what invariant holds here?" and break exactly that: negative/zero/huge/decimal/overflow values, currency swap, skipped step, replayed step, reordered steps.
- Tamper client-trusted fields: `price`, `amount`, `qty`, `discount`, `plan`, `status`, `role`, `total`.
- Parallel/duplicate submits (overlaps with race conditions — see `race-conditions.md`).
- Compare what the UI *allows* vs what the API *accepts* (remove the client-side guard).

## Minimum-evidence bar
A concrete **broken invariant with real-world consequence you demonstrate**: paid less/nothing, got credit/goods you didn't pay for, extended a trial indefinitely, escalated a role, moved money. Mirror `../../references/validation-gate.md`: "the API accepted a weird value" is not enough — show the *outcome* (order created at $0, balance increased, feature unlocked). Prove once, on your own account/order.

## Depth ladder
1. Value tampering: set `price`/`amount`/`discount` to 0 or negative; confirm the order/charge reflects it.
2. Quantity/currency abuse: negative qty for credit, cheaper currency, integer overflow.
3. Coupon logic: stack, reuse single-use, apply after total, apply to non-eligible items.
4. State skipping: reach "paid"/"shipped"/"approved" without the gating step.
5. Quota/trial reset loops: re-trigger the bonus/referral/trial grant.
6. Ownership/role transitions that grant more than intended.
7. Combine with a race to multiply (double-spend) — `race-conditions.md`.

## Bypass notes
Client-side only guards → hit the API directly. Server recomputes price? → tamper the *line-item* or the coupon, not the total. Idempotency keys → vary them to replay. No injection encoding tricks here — the payload is a *value*, so the "bypass" is finding which field the server trusts.

## Chain potential
Logic flaw → financial loss (direct payout driver). Role-assignment logic → priv-esc → admin. Quota abuse → resource/cost exhaustion. Ownership transfer → cross-account takeover. See `../../references/chaining.md`.

## Real paid example
Checkout accepted a client-sent `discount_pct`; the server applied it without validating it against the coupon catalog. Sending `discount_pct: 100` produced a $0 completed order for any item. Reproduced once on a test SKU. Band: **$1k–$6k** (direct financial, easy repro).

## Rejected variants
- "The API accepts a negative number" with no resulting benefit or loss.
- Race-free duplicate that the server correctly dedupes.
- Coupon that works as documented.
- "I could order 10,000 items" with no price/limit break and no completed abuse.
- Self-inflicted states with no attacker gain.
