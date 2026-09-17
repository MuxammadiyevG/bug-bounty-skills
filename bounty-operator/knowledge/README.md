# knowledge/ — the in-repo depth base

The engagement brain (`../SKILL.md`) governs *how* to hunt. This directory carries *what* each bug is
and how to prove it — read on trigger, never all at once. Route here from `../references/per-class-index.md`.

## Layout

```
knowledge/
├── vuln-classes/        # one file per web2 class: root-cause → detect → evidence bar → depth ladder → chain → paid example → rejected variants
├── payloads/            # per-class payload arsenals, grouped by depth tier, with a "stop when" (evidence) line
├── bypass-tables.md     # SSRF-IP / open-redirect / file-upload / 403-401 / WAF bypass tables
├── disclosed-patterns.md# recurring patterns distilled from disclosed reports, grouped by class
└── enterprise-matrices.md# M365 / Okta / vCenter / SSL-VPN attack matrices (authorized testing)
```

## How to use

1. Rank classes by value in `../references/high-value-classes.md`.
2. Commit to a class → open `vuln-classes/<class>.md`, read it before touching the target.
3. Pull payloads from `payloads/<class>.md`; climb the full depth ladder, don't spray five.
4. Check `bypass-tables.md` when a filter/WAF blocks; `disclosed-patterns.md` for the tell that reveals the class.
5. Return through `../references/validation-gate.md` → `../references/chaining.md` → `scripts/ledger.py`.

## Discipline reminder

Every file's **Minimum-evidence bar** mirrors `../references/validation-gate.md`: prove *impact*, not a
200; prove with the minimum data (one record, one key, one field); then **stop**. Never bulk-exfiltrate.
Extended (non-web) domains live one level up in `../domains/`.
