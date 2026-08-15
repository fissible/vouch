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

**Nothing was ever outside the gate**, but the reason is narrower than first
recorded, and the correction matters for how these slices may be used.

`--class` was described here as a clean namespace prefix filter. It is looser
than that. Filtering on `Fissible\Vouch\Flow` also executed
`src/Http/FlowResultHandler.php` and `src/Http/FlowResultSerializer.php`, which
are in a different namespace and merely share the leading word of their short
names. So a per-namespace slice is **over-inclusive and not a partition**.

Two consequences:

1. **Gate scope is still complete.** `Fissible\Vouch` is a genuine superset —
   every class in the package begins with it — so the full-scope run measures
   everything regardless of how the matching works underneath.
2. **The checklist cannot be validated by summing slices.** Overlapping,
   over-inclusive slices can leave a file un-run while every namespace looks
   covered. Validate against the FULL-scope run instead (see below).

What was under-counted was the per-namespace AUDIT checklist — the thing that
decides whether a human has looked at each survivor — not the measured scope.

That distinction is the reason to write the list down rather than recall it: the
gate would still have reported a number, and the number would still have been
honest, while four namespaces went un-audited behind it.

## What a per-namespace slice is, and is not

**Discovery aid only.** A slice finds survivors to look at. It is not a coverage
partition and its scores are not additive:

- Slices **over-include** — filtering on `Fissible\Vouch\Flow` also ran
  `src/Http/FlowResult*.php`.
- Slices therefore **overlap**, so per-namespace scores cannot be averaged,
  summed, or combined into a headline number.
- Namespace completion proves nothing about file coverage. Only the full-scope
  `RUN`-line-to-`src/` diff does.

The one authoritative completeness check is the diff described under *Before the
final gate*.

## Zero-mutation files — per-file evidence

A file absent from the full run is only acceptable if it has **no mutable
statements by construction**, and that must be shown per file. Namespace
completion is not evidence.

| File | Construct | Evidence |
|---|---|---|
| `src/Flow/FlowResult.php` | interface | `interface FlowResult {}` — empty body, no methods |
| `src/Flow/Authenticated.php` | `final readonly class` | Body is one constructor, promoted properties only (`AuthSuccess $success`, `ScreenSpec $screen`); no statements |
| `src/Flow/Continuing.php` | `final readonly class` | Body is one constructor, promoted properties only; no statements |
| `src/Flow/RecoveryGraceStarted.php` | `final readonly class` | Body is one constructor, promoted properties only (`int $userId`, `string $boundContext`, `ScreenSpec $screen`); no statements |
| `src/Tenancy/NullTenantResolver.php` | `final class` | One method, whose entire body is `return null;` — no operator, literal or branch to mutate |
| `src/Contracts/*.php` (all 6) | `interface` | Method signatures only, no bodies — verified by count: 6 files, 6 declaring `interface` |
| `src/Support/SystemClock.php` | `final class` | One method: `return Carbon::now('UTC')->toDateTimeImmutable();` — a delegation with no operator, literal or branch |
| `src/Support/SystemRandomSource.php` | `final class` | One method: `return random_int($min, $max);` — a delegation, both operands parameters |

Extend this table as later namespaces are audited. A file appearing in the diff
for any other reason is a hole in the gate, not an exemption.

## A 0% namespace is not automatically an untested one

`Support` measures 0.00%, and that number is misleading in a way worth recording
before anyone reads a scoreboard.

Only one of its three files produces mutants at all — `DatabaseTime.php` — and
all 15 of them sit on one `InvalidArgumentException` message. The SQL fragments
the class exists to build are covered by `tests/Database/DatabaseTimeTest.php`,
which asserts each driver's string exactly; string literals simply are not
mutated, so that coverage earns no score. The other two files are single-method
delegations with nothing to mutate.

So `Support` reads 0% while being, in substance, adequately tested. The reverse
error is the dangerous one — `Persistence` also read 0%, and there it meant 39
genuinely untested mutants. **The score does not distinguish them; only reading
the survivors does.** That is the argument for the audit gate being survivor
review rather than a threshold.

## Checklist

| # | Namespace | Files | Audited |
|---|---|---|---|
| 1 | `Fissible\Vouch` | 2 | ☑ 47.37% measured — survivors open |
| 2 | `Fissible\Vouch\Attempts` | 6 | ☑ 67.82% audited |
| 3 | `Fissible\Vouch\Attempts\Mutations` | 4 | ☑ 77.78% measured — 2 open |
| 4 | `Fissible\Vouch\Console` | 1 | ☑ 0.00% measured — 3 open |
| 5 | `Fissible\Vouch\Contracts` | 6 | ☑ zero mutations (evidenced) |
| 6 | `Fissible\Vouch\Enrollment` | 3 | ☑ 71.11% |
| 7 | `Fissible\Vouch\Factors` | 7 | ☑ 79.23% (with Drivers) |
| 8 | `Fissible\Vouch\Factors\Drivers` | 6 | ☑ |
| 9 | `Fissible\Vouch\Flow` | 10 | ☑ audited (AuthFlow 95.63%) |
| 10 | `Fissible\Vouch\Http` | 5 | ☑ 78.98% audited |
| 11 | `Fissible\Vouch\Http\Middleware` | 2 | ☑ 79.31% audited |
| 12 | `Fissible\Vouch\Models` | 10 | ☑ 76.19% measured — survivors open |
| 13 | `Fissible\Vouch\Models\Concerns` | 4 | ☑ covered by the Models run |
| 14 | `Fissible\Vouch\Notifications` | 1 | ☑ 0.00% measured — 9 open |
| 15 | `Fissible\Vouch\Persistence` | 3 | ☑ audited (violation identity) |
| 16 | `Fissible\Vouch\Recovery` | 2 | ☑ 83.82% audited |
| 17 | `Fissible\Vouch\Secrets` | 2 | ☑ audited + disclosure fixed |
| 18 | `Fissible\Vouch\Sessions` | 5 | ☑ 63.33% audited |
| 19 | `Fissible\Vouch\Support` | 3 | ☑ 0.00% — adequately tested, see above |
| 20 | `Fissible\Vouch\Tenancy` | 1 | ☑ zero mutations (evidenced) |

**All 20 measured. 12 audited to disposition; 5 measured with survivors still open (`Fissible\Vouch` root, `Models`, `Console`, `Notifications`, `Attempts\Mutations`); 2 are evidenced zero-mutation namespaces.**

Measurement is not the gate — see *The gate* in the survivor-audit document. A namespace counts as done only when every survivor, timeout and uncovered mutation there is killed or dispositioned.

Excluded, and gated separately at 80 / 95: `Kernel\Assurance`, `Kernel\Attempt`,
`Kernel\Enumeration`, `Kernel\Factor`, `Kernel\Policy`, `Kernel\Satisfiability`,
`Kernel\Screen`.

## Before the final gate

Two checks, not one.

**1. Regenerate this list and diff it against the table.** A namespace added
after this audit would be inside the measured scope automatically and outside the
audit silently — the failure this file exists to prevent.

**0. Verify the run did not truncate — it exits 0 when it did.**

The first authoritative attempt died with `Allowed memory size of 134217728 bytes
exhausted` after covering **12 of 73 files**, and **reported exit code 0**. Its
log opened with a green test suite and a plausible `Duration:` line. Nothing in
the exit status, the summary, or a casual read of the output said the run was a
twelfth of a run.

So before reconciling, check all three:

```bash
grep -c "Fatal error" /tmp/FULLSCOPE.log            # must be 0
grep -oE "[0-9]+ Mutations for [0-9]+ Files" …      # files CREATED
awk '/^   RUN /{print $2}' … | sort -u | wc -l      # files RUN — must match
```

Run it with a raised limit: `php -d memory_limit=4G vendor/bin/pest --mutate …`.

Had the file-level diff not been part of the gate, this run would have "passed"
on twelve files. That is the entire argument for reconciling against `src/`
rather than trusting a headline.

**2. Account for every file in the full-scope run.** Because slices over-include
and do not partition, per-namespace coverage does not add up to file coverage.
Take the `RUN` lines from the full-scope pass and diff them against `src/`:

```bash
vendor/bin/pest --mutate --class="Fissible\Vouch" --ignore="Fissible\Vouch\Kernel" \
  | sed -e 's/\x1b\[[0-9;]*m//g' | awk '/^   RUN /{print $2}' | sort -u > /tmp/ran.txt
find src -name '*.php' | grep -v '^src/Kernel/' | sort > /tmp/all.txt
comm -13 /tmp/ran.txt /tmp/all.txt   # files with NO mutations
```

Every file in that difference must be explainable as **zero mutations by
construction**, not merely absent. Four `src/Flow` files are already in it and
were checked individually: `FlowResult.php` is an empty interface, and
`Authenticated.php`, `Continuing.php` and `RecoveryGraceStarted.php` are readonly
DTOs whose bodies are nothing but promoted constructor properties. A file that
appears there for any other reason is a hole in the gate.
