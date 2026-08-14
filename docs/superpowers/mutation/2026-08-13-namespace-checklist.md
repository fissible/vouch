# Non-kernel mutation gate — namespace checklist

**Derived from the source, not from recollection.** Regenerate with:

```bash
grep -rhoE "^namespace Fissible\\\\Vouch[A-Za-z\\\\]*;" src/ | sed 's/^namespace //; s/;$//' | sort -u
```

## Reconciliation

An earlier progress note listed "12 namespaces remaining" and then enumerated 13.
Deriving the list from `src/` corrects both the count and its contents.

- **109 PHP files under `src/`, all 109 namespaced under `Fissible\Vouch`.** No
  file sits outside the scope.
- **27 namespaces total; 7 are `Kernel\*` and excluded; 20 are in scope.**
- The remembered list omitted **four** in-scope namespaces, and the omissions
  were not trivial ones:
  - `Fissible\Vouch` — the root, holding `Vouch.php` and `VouchServiceProvider.php`.
    The provider is where every binding in the package is wired.
  - `Fissible\Vouch\Attempts\Mutations` — the store-owned single-use mutations.
  - `Fissible\Vouch\Http\Middleware` — `ValidatesVouchSession` and `RequireAssurance`.
  - `Fissible\Vouch\Models\Concerns`

**Nothing was ever outside the gate.** Pest's `--class` is a PREFIX filter, so
`--class="Fissible\Vouch"` already covers every namespace below it. Verified
directly: the run filtered on `Fissible\Vouch\Factors` executed
`src/Factors/Drivers/*` as well as `src/Factors/*`. What was under-counted was
the per-namespace AUDIT checklist — the thing that decides whether a human has
looked at each survivor — not the measured scope.

That distinction is the reason to write the list down rather than recall it: the
gate would still have reported a number, and the number would still have been
honest, while four namespaces went un-audited behind it.

## Checklist

| # | Namespace | Files | Audited |
|---|---|---|---|
| 1 | `Fissible\Vouch` | 2 | ☐ |
| 2 | `Fissible\Vouch\Attempts` | 6 | ☐ |
| 3 | `Fissible\Vouch\Attempts\Mutations` | 4 | ☐ |
| 4 | `Fissible\Vouch\Console` | 1 | ☐ |
| 5 | `Fissible\Vouch\Contracts` | 6 | ☐ |
| 6 | `Fissible\Vouch\Enrollment` | 3 | ☑ 71.11% |
| 7 | `Fissible\Vouch\Factors` | 7 | ☑ 79.23% (with Drivers) |
| 8 | `Fissible\Vouch\Factors\Drivers` | 6 | ☑ |
| 9 | `Fissible\Vouch\Flow` | 10 | ☐ |
| 10 | `Fissible\Vouch\Http` | 5 | ☐ |
| 11 | `Fissible\Vouch\Http\Middleware` | 2 | ☐ |
| 12 | `Fissible\Vouch\Models` | 10 | ☐ |
| 13 | `Fissible\Vouch\Models\Concerns` | 4 | ☐ |
| 14 | `Fissible\Vouch\Notifications` | 1 | ☐ |
| 15 | `Fissible\Vouch\Persistence` | 3 | ☐ |
| 16 | `Fissible\Vouch\Recovery` | 2 | ☐ |
| 17 | `Fissible\Vouch\Secrets` | 2 | ☐ |
| 18 | `Fissible\Vouch\Sessions` | 5 | ☐ |
| 19 | `Fissible\Vouch\Support` | 3 | ☐ |
| 20 | `Fissible\Vouch\Tenancy` | 1 | ☐ |

**3 of 20 audited. 17 remain.**

Excluded, and gated separately at 80 / 95: `Kernel\Assurance`, `Kernel\Attempt`,
`Kernel\Enumeration`, `Kernel\Factor`, `Kernel\Policy`, `Kernel\Satisfiability`,
`Kernel\Screen`.

## Before the final gate

Regenerate this list and diff it against the table. A namespace added after this
audit would be inside the measured scope automatically and outside the audit
silently — which is exactly the failure this file exists to prevent.
