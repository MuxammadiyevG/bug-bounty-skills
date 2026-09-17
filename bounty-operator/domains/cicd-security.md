# CI/CD Security

> One-line: load when a target has public repos with CI pipelines (GitHub Actions, GitLab CI, CircleCI, Jenkins); yields secret exfiltration, code execution in build infra, and supply-chain compromise that chains straight to critical.

## When to load this
- Target org has public GitHub/GitLab repos, especially with `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/`.
- Repos accept external PRs (fork-based contributions) — the classic attack surface.
- You see self-hosted runners, OIDC-to-cloud federation, or workflows that echo/use untrusted input.
- Recon surfaced package names, internal registries, or dependency manifests (dependency-confusion candidates).

## Toolchain
Missing tools are skipped, not errors — adapt.
- **`sisakulint`** — static linter for GitHub Actions security anti-patterns (injection, missing permissions, unpinned actions).
- **`actionlint`** — general Actions linting; surfaces expression/context misuse.
- **`gh` CLI + git** — enumerate workflows, run history, artifacts, org repos.
- **`gitleaks`/`trufflehog`** — secrets in the repo + full git history (feeds and overlaps with CI abuse).
- **Manual `grep` over workflow YAML** — the real work; the linters miss context-specific logic.
- **`nuclei`/custom** — probe exposed Jenkins/self-hosted runner endpoints if in scope.

## Workflow
1. **Inventory pipelines.** `gh api` / clone; list every workflow, its triggers, `permissions:` block, referenced actions (and whether pinned to SHA vs a mutable tag), secrets used, and whether it deploys or touches cloud.
2. **Hunt GitHub Actions workflow injection.** The core bug: **untrusted input flowing into a shell `run:` step via `${{ }}` interpolation.** Attacker-controlled fields — `github.event.pull_request.title`, `.body`, `head_ref`, `.comment.body`, issue title — interpolated into `run: echo "${{ github.event.pull_request.title }}"` = shell injection executing in the runner. Grep:
   `grep -rnE '\$\{\{\s*github\.(event|head_ref|.*\.body|.*\.title)' .github/workflows/`
   Injectable contexts must be passed via `env:` and quoted `"$VAR"`, never inlined.
3. **Flag `pull_request_target` — the crown jewel.** This trigger runs with the **base repo's secrets and a read/write token**, but on code from the fork's PR. If such a workflow checks out and *executes* PR code (`actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}` then build/test/install), an attacker's fork runs arbitrary code with full secret access. Also watch `workflow_run` and `issue_comment`. Grep `grep -rn 'pull_request_target' .github/workflows/`.
4. **Trace secret exfiltration paths.** Once you have code exec in a privileged workflow: secrets land in env/memory. Model exfil — echo to logs (base64 to dodge masking), POST to attacker host, or write to an artifact. `${{ secrets.* }}` in an injectable step, or a step that dumps `env`, is the smoking gun.
5. **Self-hosted runner poisoning.** Self-hosted runners on public repos are dangerous: PR jobs execute on infra the org controls, often **non-ephemeral** (state persists between jobs) and network-adjacent to internal systems. Look for `runs-on: [self-hosted, ...]` on fork-triggerable workflows → RCE on internal infra, lateral movement, credential harvest from the runner.
6. **OIDC token theft.** Workflows federate to AWS/GCP/Azure via OIDC (`id-token: write`). If you get code exec in such a workflow, you can request the OIDC token and assume the cloud role — often over-scoped, with a loose `sub` trust condition. Check `permissions: id-token: write` + the cloud role's trust policy conditions (a wildcard `sub` = any repo/branch can assume it).
7. **Dependency confusion.** Extract internal package names from manifests/lockfiles/`.npmrc`/registry config. If an internal name is unclaimed on the public registry (npm/PyPI/etc.), a malicious public package of the same name may be pulled by the build (higher version wins) → code exec in CI. Confirm the name is unregistered publicly before claiming.
8. **Supply-chain / unpinned actions.** Third-party actions pinned to a mutable tag (`@v3`, `@main`) instead of a full commit SHA = the action author (or a repo compromise) can push malicious code that runs with your secrets. Flag every unpinned `uses:`.

## Evidence bar
- A **PoC PR/comment** (on a fork you control, targeting a test scenario permitted by scope) that demonstrably executes injected commands or reads a secret — with the run log as proof. Never exfiltrate real production secrets; prove capability with a benign marker (e.g. print a controlled canary, not the secret value).
- For OIDC: proof the federated role is assumable with an over-broad trust condition (the condition text + the `id-token: write` grant), ideally a benign STS call.
- For dependency confusion: the internal package name + proof it's unclaimed publicly + the build step that would resolve it externally.
- Not evidence: an unpinned action with no injectable path; a `pull_request_target` workflow that never checks out or runs PR code; a linter warning with no exploit reasoning.

## Feed back into the flow
Plugs into ../SKILL.md Operational Flow phases 4–8:
- **4 MODEL & RANK** — model the pipeline as its own trust boundary: who can trigger it, with what token/secrets, on whose code. Rank fork-triggerable + privileged workflows first.
- **5 HUNT** — the injection/`pull_request_target`/runner/OIDC/confusion sweep is the hunt.
- **6 VALIDATE** — prove code exec or secret reach with a benign PoC before claiming; capability, not a hypothetical.
- **7 CHAIN** — this domain is a *chain amplifier*: workflow injection → secret → cloud/prod → critical; runner poisoning → internal lateral movement; OIDC theft → cloud account takeover.
- **8 REPORT** — impact = what the leaked secret/role/RCE reaches (prod deploy keys, cloud admin). Include the exact YAML lines and the injectable context.

## Pitfalls
- Confusing `pull_request` (no secrets, runs fork code safely) with `pull_request_target` (secrets + write token) — only the latter is the high-severity trigger.
- Actually exfiltrating a real secret in your PoC — prove capability with a canary; dumping live prod secrets can breach the program and burn you.
- Reporting an injectable `${{ }}` that only ever sees trusted maintainer input (not fork-controllable) — check who controls the field.
- Assuming any self-hosted runner is exploitable — ephemeral runners on private-only workflows are much lower risk; confirm fork-triggerability.
- Claiming dependency confusion without verifying the internal name is genuinely unclaimed on the public registry.
- Testing against production pipelines in a way that pollutes releases or triggers real deploys — stay benign and in scope.
