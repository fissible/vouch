# The no-candidate files — 25 of 44 rows ruled

The manifest's check 2 left 63 rows unjoined. 44 of those sit in files that no
ruling document covered at all. This rules **25** of the 44, by expression and
dataflow. The remaining 19 are listed at the end, still open.

Every ruling below is a measurement: the mutation was applied to the source, the
suite re-run, and the result recorded either way.

## Killed — 11 rows

### `Http/AssuranceComparator:24` — 4 rows — KILLED

`private const ORDER = ['aal0', 'aal1', 'aal2', 'aal3']` — the assurance lattice.
`isSufficient()` compares `array_search` indices, so dropping a level makes it
unrecognised and returns `false`: a legitimately-assured session is refused. That
is the lockout the file's own docblock warns about — *"refusing a stronger
session is a lockout that looks like a security win."*

Measured, one removal at a time against the full suite:

| removed | result |
|---|---|
| `aal0` | 1 failed |
| `aal1` | 3 failed |
| `aal2` | 4 failed |
| `aal3` | 1 failed |

**The existing tests already kill all four.** The runner reports them `UNCOVERED`
because a `const` declaration line carries no coverage attribution, so no test is
ever selected for it — *uncovered is not untested*, and it is worth checking
which of the two an uncovered row actually is before ruling it.

### `Support/DatabaseTime:60` — 5 of 15 rows — KILLED

`DatabaseTimeTest` asserted `->throws(InvalidArgumentException::class)` and
nothing about the message. `InvalidArgumentException` is SPL and anything can
raise it, so the assertion would stay green if an unrelated defect threw first —
and said nothing about whether an operator can tell *which* driver is
unsupported, the only actionable content the message carries. That is the
standing rule about asserting messages when the class is broad.

Now `toThrow(InvalidArgumentException::class, 'oracle')`. Re-measured: 5 of the
15 rows die — precisely those that drop `$driver` from the message.

### `Recovery/GraceGuard:51,52` — 2 rows — KILLED

`'created_at'` / `'updated_at'` in the grace-session insert. `$table->timestamps()`
is nullable, so dropping either leaves a usable row and every other grace
assertion green — while `AuthSession` declares both as non-null `Carbon`. A model
whose declared type is contradicted by its own writer is a defect that only
surfaces at the reader.

`it('stamps the row it creates, from the database clock')` in `GraceGuardTest`.
Verified both ways: removing either stamp fails it.

### `Flow/AuthFlow:236` — 1 row — KILLED

`return new Continuing($this->screens->challenge(...), $attempt->handle)` on the
not-yet-Authenticated branch. Removing it drops a half-satisfied attempt straight
through into the Authenticated transition below.

`it('continues with the next factor when the policy is only partly satisfied')`.

**The first version of this test did not kill it, and the reason is the standing
rule in miniature.** Asserting `toBeInstanceOf(Continuing::class)` and the handle
passes under the mutant too: the fall-through lands on `$refusal()`, which also
returns a `Continuing` carrying the same handle. The artifact that distinguishes
the two is the **screen** — an offer of the next factor carries no errors, a
refusal carries `CredentialRejected`. Asserting `$result->screen->errors === []`
kills it.

## Equivalent — 12 rows

### `Support/DatabaseTime:60` — 10 rows — PROSE

The survivors after the strengthened assertion are exactly those that leave
`$driver` in place: reorderings and truncations of the advisory sentences around
it. Checked against the three disqualifying conditions used for the 46 exception
rows: not a protocol value (the SQL strings on lines 56–58 are single literals
with no PHP concatenation, so no mutator touches them); `getMessage()` consumed
nowhere in `src/`; `InvalidArgumentException` caught nowhere in `src/`. The
discriminating content is asserted, the wording of the advice is not — which is
correct for prose.

### `Attempts/DatabaseAttemptStore:113` — 1 row — EQUIVALENT

`$seen[$target] = true` → `false`. The only read is `isset($seen[$target])`, and
`isset()` is false only for null or absent. The value is never examined; key
presence is the whole mechanism. Equivalent by language semantics.

### `Flow/AuthFlow:101` — 1 row — EQUIVALENT (schema-conditional)

`'version' => 1` in `AuthAttempt::create`. The migration declares
`$table->unsignedBigInteger('version')->default(1)`, so the explicit value is
redundant. Premise: that column default. Suite stays green with the key removed.

## Compensating control — 1 row

### `Attempts/DatabaseAttemptStore:37` — 1 row

`$mutations = array_values($mutations)`. `transition()` is variadic, and the
source documents why the call is there: PHP 8.1+ lets a variadic receive named
arguments, so its native type is `array<int|string, …>` rather than a list.

At runtime it is equivalent — every consumer is a `foreach`, which visits the
same values in the same order regardless of keys. But the two private helpers
declare `@param list<SingleUseMutation>`, and **removing `array_values` fails
PHPStan level 9** with `expects list<…>` on both call sites. Measured, not
argued. The static analyser is the control, and it runs in CI, so the row is
covered — by a different instrument than the mutation runner, which is why the
runner cannot see it.

## Still open — 19 of the 44

| File | Rows | Shape |
|---|---|---|
| `Http/Middleware/RequireAssurance:51` | 6 | `RuntimeException` message, fail-closed step-up config |
| `Vouch.php:42` | 6 | `RuntimeException` message, embeds `$level` |
| `Factors/FactorRegistry:29` | 4 | `LogicException` via `sprintf`, write-once registration |
| `Flow/AuthFlow:329, 387` | 2 | `RemoveEarlyReturn` on `$userId === null` guards |
| `Flow/AuthFlow:243` | 1 | `RemoveEarlyReturn` on the failed-transition refusal, uncovered |

The three message sites look like the `DatabaseTime` case and should get the same
treatment rather than a blanket prose ruling: check whether any test asserts the
message, and where the class is broad and the message carries a discriminating
value — `Vouch.php:42` embeds `$level` — assert that value first, then rule the
remainder prose.

`AuthFlow:329` and `:387` are the same `$userId === null` guard pattern that
`2026-08-14-driver-rulings.md` ruled equivalent on a tested premise; that
correspondence needs establishing rather than assuming.

**25 of 44 ruled: 11 killed, 12 equivalent, 1 compensating control. 19 open.**
