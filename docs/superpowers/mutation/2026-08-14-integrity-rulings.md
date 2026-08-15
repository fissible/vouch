# IntendedDestination, SessionRotationFailed, ChallengeTargetViolation — 29 rows

## `IntendedDestination` — 14 rows — COMPENSATING CONTROL

Every surviving row is a **redundant arm** of the layered redirect validator, and
the split matches the overlap measured earlier exactly: the arms that are
uniquely load-bearing were killed and do not appear in the manifest at all.

| Rows | Expression | Compensated by |
|---|---|---|
| 2 | L76 — the `//` prefix pair | `parse_url` exposes `host`, caught at L87–89 |
| 1 | L77 `return null` | the authority-component check below it |
| 1 | L82 `$parts === false` | a false parse yields no `path`, caught at L95 |
| 1 | L83 `return null` | same |
| 1 | L87 `ForeachEmptyIterable` | the `//` prefix check above |
| 5 | L87 `RemoveArrayItem` (scheme/host/port/user/pass) | the remaining four components, plus the prefix check |
| 1 | L89 `return null` | the `//` prefix check above |
| 1 | L95 `BooleanOrToBooleanAnd` | the authority components above |
| 1 | L96 `return null` | same |

**Not killed, and not a gap.** `tests/Http/OpenRedirectTest.php` enumerates
eleven documented bypasses and every one is refused; these mutants survive
because a *second* arm refuses the same input independently. The arms whose
inputs no other arm catches — the literal backslash and the `%2f`/`%5c`
encodings, which produce a path starting with `/` and carrying no authority —
are killed and absent from the manifest.

Keep every arm. The redundancy defends against a future in which `parse_url`'s
behaviour, a PHP upgrade, or an added pre-normalisation step changes which arm
fires first, and a redirect validator is where that margin is worth paying for.

## `SessionRotationFailed` — 8 rows

| Rows | Expression | Ruling |
|---|---|---|
| 6 | L24 message | **Prose** — thrown, developer-facing |
| 2 | L27 exception code `0` | **Equivalent** — Vouch never reads the code; `SessionLifecycle` catches the class and the fail-closed path is asserted by `SessionRotationFailureTest` |

## `ChallengeTargetViolation` — 7 rows

| Rows | Expression | Ruling |
|---|---|---|
| 6 | L21, L44 messages | **Prose** — thrown, and their *identity* is separately pinned by `ViolationIdentityTest` |
| 1 | L47 `RemoveStringCast` on `(string) $attemptUserId` | **Equivalent** — the value is consumed by `sprintf('%s')`, which renders an int identically. The live logic on that line is the null-vs-owned ternary, and that IS tested |

**29 of 29 ruled: 14 compensating control, 12 prose, 3 equivalent.**
