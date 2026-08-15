# The 19 candidate rows — 19 of 19 ruled

The rows the regenerated manifest could not discharge because their candidate
documents make no exhaustive claim. **Re-derived from a fresh run against current
source**, not read off the old table.

`2026-08-15-cast-classification.md`'s matrix section is **retracted and is not
evidence here**. Rows previously attributed to it were re-derived from the engine
findings in `2026-08-15-matrix-rulings.md`: on PHP 8.4, `pdo_mysql`, `pdo_pgsql`
and `pdo_sqlite` all return a native `int` for an integer column, pinned by
`it('hands back a PHP int for an integer column with no cast involved')`.

That re-derivation immediately corrected three attributions. `AuthConnection`,
`AuthIdentifier` and `AuthFederatedIdentity` were filed under the cast document,
but their surviving rows are not cast rows at all — they are
`DecrementInteger` / `IncrementInteger` on value-bound maxima and a
`RemoveArrayItem` on a `$hidden` array. Filename attribution had put them under a
document that never ruled them.

Referenced by **(file, expression, mutator)**. Line numbers and mutation IDs both
drift — `EnrollmentGuard` moved 97 → 111 under a docblock edit — so neither is
used as identity.

## Killed — 10 rows

| File | Expression | Mutator | How |
|---|---|---|---|
| `Models/AuthCredential` | `protected $hidden = ['secret']` | RemoveArrayItem | existing disclosure tests, 2 failures |
| `Models/AuthConnection` | `protected $hidden = ['client_secret']` | RemoveArrayItem | existing disclosure tests, 1 failure |
| `Models/AuthAttempt` | `'tenant_id' => ['max' => 255]` | DecrementInteger | new at-bound acceptance test |
| `Models/AuthConnection` | `'tenant_id' => ['max' => 255]` | DecrementInteger | new at-bound acceptance test |
| `Models/AuthPolicy` | `'tenant_id' => ['max' => 255]` | DecrementInteger | new at-bound acceptance test |
| `Models/AuthIdentifier` | `'value' => ['max' => 255]` | DecrementInteger | new at-bound acceptance test |
| `Models/AuthFederatedIdentity` | `'issuer' => ['max' => 255, 'ascii' => true]` | IncrementInteger | new one-over refusal test |
| `Http/FlowResultSerializer` | `return match (true)` in `toArray()` | TrueToFalse | existing tests, 15 failures |
| `Http/FlowResultHandler` | `return match (true)` in `handle()` | TrueToFalse | existing tests, 27 failures |
| `Http/AuthController` | `action: is_string($action) ? $action : null` | TernaryNegated | new action-passthrough test |

### The two `$hidden` arrays and the two `match (true)` heads

All four were reported `UNCOVERED` and all four are killed by tests that already
existed. A property declaration and a `match` subject line carry no coverage
attribution, so the runner never selects a test for them. **That is the fourth
and fifth time in this audit that `UNCOVERED` meant "not routed" rather than
"not tested"** — it has to be checked per row, in both directions, because
`AuthFlow:243` was the opposite case: uncovered *and* a real fail-open.

### The five value bounds — a real gap

Every bound had a "refuses an over-length …" test submitting **256** characters,
which stays refused however far the limit is *tightened*. So narrowing any bound
to 254 left the suite green. The over-length issuer test was worse: it submits
281 characters, which stays refused however far the limit is *widened*, so
`issuer` could grow to 256 unnoticed.

A bound probed only from one side is a bound whose value is not asserted. Both
sides now exist:

- `it('accepts a tenant id and identifier value exactly at the bound')` — 255
  accepted on all four sites, which kills every `DecrementInteger`.
- `it('refuses an issuer one character over the bound')` — exactly 256, which
  kills the `IncrementInteger`.

This matters beyond mutation score: silently tightening is a lockout for a
legitimate 255-character tenant id or email, and silently widening pushes a
value that is half of a unique index toward the InnoDB key-length limit
PROJECT.md already warns about.

### `AuthController` — the action was never carried

`action` reaches exactly one decision: `AuthFlow::selectFactor()`'s
`=== 'recover'` branch, which is what lets a user submit a recovery code instead
of the policy's default factor. Negating the ternary discards every well-formed
action, so recovery through the HTTP endpoint stops working — and no test sent an
action at all.

`it('carries the submitted action through to factor selection')` drives it end to
end: with the action carried a recovery code opens grace; without it the flow
selects the default factor and the same code is refused as a bad password.
Asserted on the outcome, not by inspecting the request.

## Equivalent — 8 rows

| File | Expression | Mutator | Premise |
|---|---|---|---|
| `Models/AuthAttempt` | `'version' => 'integer'` | RemoveArrayItem | drivers return native int |
| `Models/AuthCredential` | `'last_used_timestep' => 'integer'` | RemoveArrayItem | drivers return native int |
| `Models/AuthChallenge` | `'attempts' => 'integer'` | RemoveArrayItem | drivers return native int |
| `Console/VouchPruneCommand` | `Config::integer('vouch.sessions.revocation_retention_days', 30)` | DecrementInteger | default unreachable |
| `Console/VouchPruneCommand` | same | IncrementInteger | default unreachable |
| `Factors/Drivers/PasswordFactor` | `if ($userId === null) return failed(NoCredential)` | RemoveEarlyReturn | `user_id` is NOT NULL |
| `Attempts/Mutations/ConsumeChallenge` | `'challenge:' . $this->challengeId` | ConcatSwitchSides | key only needs distinctness |
| `Http/FlowResultSerializer` | `array_map(fn (FieldSpec …) …, $screen->fields)` | UnwrapArrayMap | byte-identical JSON |

Each premise is tested, not asserted:

- **The three casts** — pinned by the PDO-int test, on all three engines. The
  retracted "MySQL and Postgres return numeric strings" claim plays no part.
- **The prune default** — `config/vouch.php` ships
  `'revocation_retention_days' => (int) env(…, 30)`, so the literal `30` in
  `Config::integer(…, 30)` is unreachable. Premise pinned by
  `it('ships a retention window in config, which is the value actually used')`.
- **`PasswordFactor`** — `2026-08-15-tail-rulings.md` recorded this row as *"Not
  yet traced."* It is now traced: falling through runs
  `where('user_id', $userId)` with a null id, which Laravel compiles to
  `where user_id is null` against a NOT NULL column, so no credential is found
  and the next guard returns `NoCredential` anyway — the identical result. Same
  premise and same ruling as `AuthFlow:329/387` and the driver rows, pinned by
  `it('cannot store a credential without an owner')`.
- **`FlowResultSerializer`'s field map** — the claim is that the mapped array and
  the raw `FieldSpec` produce identical JSON. Verified rather than inherited:
  `json_encode(new FieldSpec('code','text','one-time-code',64))` is byte-for-byte
  the mapped array. Note the equivalence holds **at the JSON boundary only** — a
  consumer reading `$data['screen']['fields'][0]['name']` as a PHP array would
  break — so the premise is "serialization is the only consumer".

## Compensating control — 1 row

| File | Expression | Mutator |
|---|---|---|
| `Factors/FactorResult` | `array_values($mutations)` in `satisfied()` | UnwrapArrayValues |

Runtime-equivalent for the same reason as `DatabaseAttemptStore`'s
`array_values`: the variadic's consumers do not depend on keys. **Removing it
fails PHPStan level 9**, measured. The static analyser is the control and it runs
in CI, so the row is covered — by a different instrument than the mutation
runner, which is why the runner cannot see it.

**19 of 19 ruled: 10 killed, 8 equivalent, 1 compensating control.**
