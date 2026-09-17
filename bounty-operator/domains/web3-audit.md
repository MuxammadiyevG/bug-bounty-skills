# Web3 / Smart-Contract Audit

> One-line: load when scope is on-chain (Solidity/EVM or Rust/Anchor on Solana, DeFi protocols, token contracts); yields fund-loss bugs paid on real value-at-risk, not CVSS theatre.

## When to load this
- Scope names a protocol, vault, AMM, lending market, bridge, staking contract, or a token/mint address.
- Immunefi / Sherlock / Code4rena / Cantina engagement, or a program that scopes `*.sol`, `programs/*.rs`, or a deployed contract address.
- Someone asks "is this token a rug?" or hands you a contract to review pre-investment.
- The real question is "can I drain, mint, freeze, or desync funds?" — not "is there an XSS."

## Toolchain
Missing tools are skipped, not errors — adapt to what is installed.
- **Foundry (`forge`/`cast`)** — fork-test the live protocol, write the PoC that proves fund loss.
- **`slither`** — fast static taint/detector pass; triage, not proof.
- **`aderyn`** — Rust-based static analyzer, good complementary detector set.
- **`cast`** — read on-chain state/storage slots, call view fns, decode calldata on a fork.
- **`heimdall`** — decompile unverified bytecode when no source is published.
- **Solana: `anchor test`, `solana-verify`, `cargo-geiger`** — Anchor account-constraint review, verify deployed program matches source.
- **`scripts/token_scanner.py`** (if present) — automated rug red-flag pass for token contracts.
- Etherscan/Solscan verified-source + Read range (RPC archive node) for state at exploit block.

## Workflow
1. **Pre-dive kill signals — bail before you sink hours.** Skip or deprioritize when: TVL < $500K (payout caps below effort), contract unverified AND no decompile budget, already audited by a top firm with no diff since, upgradeable proxy where admin can front-run any fix, or protocol is a fork of a known-safe codebase with zero custom diff. Diff-only against the upstream original when it *is* a fork.
2. **Model the money.** Where does value enter, accrue, and exit? Map: deposit/mint, share accounting, price/oracle source, withdraw/redeem, fee sink, admin levers. High-value bugs live in the accounting between two of those.
3. **Run the 10-class sweep (grep + reason), highest-frequency first:**
   - **Accounting desync** — internal balance/shares drift from real token balance. `grep -nE 'balanceOf|totalSupply|totalAssets|_balances\[' ` — look for rebasing/fee-on-transfer tokens vs `transferFrom(amount)` assumed exact; donation/direct-transfer inflating `balanceOf`.
   - **Access control** — missing/loose modifier on state-changing or fund-moving fn. `grep -nE 'function .*(public|external)' | grep -v 'onlyOwner|require\('` then eyeball each; `initialize()` without `initializer`; `selfdestruct`, `delegatecall`.
   - **Incomplete path** — a code path that skips a required update (fee not taken, reward not settled, debt not accrued before action). Trace each external fn to confirm every invariant is touched.
   - **Off-by-one / rounding** — `grep -nE '/ |\* |>=|<=|>|<'` around share math; rounding direction that favors the user (round-down on mint, round-up on burn is the safe direction — flag the inverse).
   - **Oracle manipulation** — spot price from a DEX pair used directly. `grep -nE 'getReserves|slot0|price0|latestAnswer|getAmountsOut'` — `getReserves()`/`slot0()` as price = manipulable; TWAP window too short; stale `latestAnswer` (no `updatedAt`/`answeredInRound` check).
   - **ERC4626 inflation / first-depositor** — empty vault, attacker mints 1 share then donates assets to skew `convertToShares`, later depositors get 0 shares. `grep -nE 'convertToShares|convertToAssets|totalAssets|4626'` — check for virtual shares/dead-shares mitigation.
   - **Reentrancy** — external call before state update. `grep -nE '\.call\{|\.transfer\(|safeTransfer|onERC721Received|_mint\('` — classic single-fn, plus **cross-function** and **read-only** reentrancy (view returns stale price mid-callback). Check for `nonReentrant` on *all* related fns, not just one.
   - **Flash-loan-amplified oracle/logic** — any per-tx invariant an attacker can satisfy with borrowed capital: manipulate spot oracle, skew pool ratio, trigger liquidation threshold, govern with borrowed votes. Assume attacker has unlimited single-tx capital.
   - **Signature replay** — EIP-712/permit without nonce, chainId, or deadline; sig reusable across forks/contracts. `grep -nE 'ecrecover|permit|EIP712|_domainSeparator|nonces'`.
   - **Proxy / upgrade** — uninitialized implementation, storage-layout collision on upgrade, unprotected `upgradeTo`, `delegatecall` to attacker-controlled address. `grep -nE 'delegatecall|_implementation|upgradeTo|__gap|initializer'`.
4. **Solana/Anchor specifics.** Missing `has_one`/`Signer`/owner checks, account substitution (attacker passes a look-alike account), missing `#[account(mut)]` reload, arbitrary CPI to unchecked program, PDA seed collision, integer overflow in non-`checked_` math, `close` without zeroing.
5. **Token / meme-coin rug vectors** (any token in scope, EVM or SPL): hidden mint fn behind obfuscated modifier; honeypot (buy works, `transfer`/sell reverts for non-owner via blacklist/max-tx); mutable fee that owner can set to ~100%; LP-lock bypass (owner keeps a withdraw path or lock is a no-op/short); Solana **freeze authority** or **mint authority** still set; metadata mutable; "renounce" that's fake (ownership moved to a still-controlled contract, or a second privileged role remains). Run `scripts/token_scanner.py` if present, then confirm each hit by hand.
6. **Write the Foundry PoC.** For every High/Critical, prove it on a **mainnet fork** at a real block: `forge test --fork-url $RPC --fork-block-number N`. The test must assert measurable fund movement (attacker balance up, protocol down). No PoC = not a Critical, no matter how clean the reasoning.

## Evidence bar
- A passing `forge` (or `anchor`) test on a fork that moves real value: `assertGt(attackerAfter, attackerBefore + gas)` with protocol assets provably lost.
- Exact loss quantified in tokens/USD at a stated block — this is the payout basis.
- Named invariant broken (e.g. "shares minted without proportional assets") with the storage slots/lines.
- For rugs: the specific privileged call sequence that drains or freezes holders, reproduced on a fork.
- Not evidence: a slither warning, a "theoretically" reentrancy with a `nonReentrant` guard already present, a rounding error of 1 wei with no path to amplification.

## Feed back into the flow
Plugs into ../SKILL.md Operational Flow phases 4–8:
- **4 MODEL & RANK** — the money-map and TVL/kill-signal triage *is* the ranking step for on-chain scope; crown jewels = fund-moving fns.
- **5 HUNT** — the 10-class sweep + Solana checks + rug vectors are the hunt.
- **6 VALIDATE** — the fork PoC is the 7-Question Gate for web3; "does it actually move funds" replaces "is the 200 real."
- **7 CHAIN** — combine primitives: oracle skew → liquidation → bad-debt socialization; first-depositor → repeated dilution; access-control gap → upgrade → drain.
- **8 REPORT** — Immunefi/Sherlock format: title = broken invariant, severity anchored to funds-at-risk, PoC pasted verbatim, exact loss stated.

## Pitfalls
- Auditing an unverified contract from the ABI alone and missing a hidden `delegatecall`/mint path — decompile or move on.
- Reporting a "reentrancy" that's already guarded, or a rounding bug with no amplification — instant N/A and reputation hit.
- Ignoring fee-on-transfer / rebasing token compatibility because the happy-path test passed with a vanilla ERC20.
- Testing against a stale local state instead of a mainnet fork at the right block — many bugs only exist against live pool ratios.
- On Solana, assuming Rust type safety covers account confusion — it does not; the *constraint* checks are the audit.
- Chasing sub-$500K TVL protocols for effort that a P1 elsewhere would out-pay. Respect the kill signals.
- Calling a token "safe" because ownership is renounced without checking for a second privileged role or a proxy admin.
