# System Modeling — model the system before you attack endpoints

> Scanners test endpoints. The bugs that pay test the *system*: who can do what, to whose data, in
> which state, across which trust boundary. Modern high-value findings — BOLA/BOPLA/BFLA, business-
> flow abuse, privilege jumps — are authorization and logic failures a scanner cannot model because
> the request looks legitimate and returns a normal 200. Spend real time here (phase 4) before hunting.

## Build five maps for the target

**1. Identity & roles.** Enumerate every principal type: anonymous, self-registered user, paid tier,
org member, org admin, support/staff, service-to-service. For each, note how it authenticates
(session, JWT, API key, OAuth) and what it is *supposed* to be able to do. Create at least **two
accounts you control at the same privilege level** (for horizontal tests) and, where possible, one at
a higher level (for vertical tests).

**2. Objects & ownership.** List the resource types (order, invoice, ticket, file, project, message)
and, for each, *who owns it* and *how ownership is expressed* — an id in the URL, a tenant claim in
the token, a foreign key. This map is your BOLA/BOPLA target list: every object read/write is a
place the server might check authentication but not ownership.

**3. Tenants & trust boundaries.** In multi-tenant SaaS, draw the tenant wall. Then find every place
data crosses it: shared caches, exports, search/autocomplete, notifications/webhooks, PDF/invoice
generation, analytics, service-to-service hops. Cross-tenant reads and writes are top-tier findings.

**4. State & sequences.** Diagram the multi-step flows: signup→verify, checkout→pay→fulfill,
invite→accept→role, reset-request→reset. Bugs hide in the *transitions* — a step that trusts a value
set in an earlier step, a state you can reach out of order, a step you can replay or skip.

**5. Property-level exposure & mass assignment.** For each object, compare what the UI shows vs. what
the API returns and accepts. Over-returned fields = BOPLA read (excessive data exposure).
Accepted-but-hidden fields (role, isAdmin, price, tenantId) = BOPLA write (mass assignment).

## Turn the maps into hypotheses (feed the hunt)

Each cell in these maps is a testable hypothesis, e.g.:
- "User B can read User A's `order` because ownership is only the URL id." → two-account BOLA test.
- "A low-tier user can call the admin-only `refund` mutation." → BFLA test.
- "Checkout trusts a `price` field set client-side in step 1." → business-logic test.
- "The invite flow lets me set `role=admin` on accept." → mass-assignment/privilege escalation.
- "Tenant A's export includes Tenant B rows via a shared query." → cross-tenant read.

## Priority order (highest expected value first)

1. Cross-tenant read/write (SaaS multiplier).
2. Object-level authorization (BOLA) on money/PII objects — read first, then the matching write.
3. Function-level authorization (BFLA) — low-priv role reaching admin functions.
4. Business-flow abuse (skip/replay/reorder steps; abuse a sensitive flow at scale).
5. Property-level (BOPLA) — over-returned fields and mass assignment.
6. Authentication / session / ATO paths.

## The two-account habit

Almost every authorization finding needs **two accounts you control** and a disciplined diff: send
the same request as A and as B, change only the id/claim, and compare bodies. Confirmed = the *other*
account's real data in the response. A 200, a reflected id, or your own data is not a finding.
Prove with one record + a count, then stop.
