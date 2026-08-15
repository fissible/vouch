# The final 30 rows

## MATRIX-REQUIRED — cannot be ruled on SQLite

Neither equivalent nor killed. A SQLite-only green test would certify nothing,
so these are discharged by Task 14 or not at all.

| Row | Why SQLite cannot decide it | Matrix proof required |
|---|---|---|
| `AuthAttempt:42` — `'version' => 'integer'` | SQLite returns an integer natively, so removing the cast is invisible. MySQL and Postgres return a numeric string, and an uncast version turns the compare-and-swap into a string comparison. | Run the typed-version/CAS assertion on MySQL and PostgreSQL, then remove the cast and confirm the engine-specific test fails. |
| `EnrollmentGuard:97` — `RemoveMethodCall` on the `lockForUpdate()` select | The method's own docblock: on SQLite `lockForUpdate` compiles to a bare SELECT and does nothing, because serialization comes from the write lock `insertOrIgnore` already took. On MySQL and Postgres that select IS the serialization. | The contention matrix on both engines, with the select removed. |

## Killed by tests added after the manifest run

The manifest was generated before these landed, so the rows are attached to the
tests that now cover them. A re-run will show them killed; the attachment is
recorded here so the join is not lost in the meantime.

| Row | Test |
|---|---|
| `FlowResultSerializer:34`, `FlowResultHandler:40` — `match (true)` | the discriminator tests: a `Continuing` result must stay inert |
| `PasswordFactor:169` — `revoke()`'s update | `RevokeContractTest`, across every registered driver |
| `AuthController:43` — `TernaryNegated` on the return target | the payload contract: `returnTo` appears on the authenticated envelope only |

## Equivalent — each re-derived

| Row | Reason |
|---|---|
| `FlowResultSerializer:70` — `UnwrapArrayMap` | Every `FieldSpec` property is a scalar whose name matches its output key; the mapped array and the raw object produce byte-identical JSON. Verified, not argued. |
| `FactorResult:33` — `UnwrapArrayValues` | A variadic is already a list. |
| `ConsumeChallenge:26` — `ConcatSwitchSides` | The target stays unique per subject and still cannot collide with `credential:<id>`; nothing persists or transmits the key, so only its distinctness matters. Note this is NOT the same ruling as the `ConcatRemoveRight` row on the same line, which was real and is killed. |

## Open — needs a test

| Row | Concern |
|---|---|
| `GuardsChallengeTarget:50` — `RemoveNullSafeOperator` on `$attempt?->user_id` | A challenge naming a missing attempt would dereference null on a persistence guard, turning a typed violation into a TypeError. |
| `PasswordFactor:133` — `RemoveEarlyReturn` | Not yet traced. |
| `VouchPruneCommand:41/48` | The retention default is dispositioned equivalent (unreachable, config always supplies the key); `:48` is the `info()` output line. |

## Remaining model rows — casts and value bounds

`AuthLinkRequest` 30–32, `AuthSession` 39/41, `AuthIdentifier` 37/50,
`AuthChallenge` 39/41, `AuthPolicy` 45, `AuthTokenAssurance` 35,
`AuthConnection` 43/44/59, `AuthFederatedIdentity` 34/51, `AuthCredential` 56–58.

Same treatment as the security-bearing casts already pinned: each needs a raw
write and a typed read-back. Several will prove **matrix-required** for the same
reason the version cast did — SQLite's native typing hides them — and that must
be established per row rather than assumed either way.
