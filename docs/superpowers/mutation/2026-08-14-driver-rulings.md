# The three factor drivers — 79 rows

Re-verified expression by expression. The earlier per-file audit's conclusions
are treated as evidence to revisit, not inherited rulings — and that refusal
found `revoke()`, an entire contract method no test had ever called.

## Killed

| Rows | Expression | Evidence |
|---|---|---|
| 2 | `TotpFactor:256`, `RecoveryCodeFactor:234` — `revoke()`'s `update(['disabled_at' => …])` | `tests/Factors/RevokeContractTest.php`: every registered driver disables on revoke; siblings untouched; and the revoked credential leaves the authentication path — the driver returns `NoCredential` and the flow refuses to authenticate |

## Equivalent — schema-conditional, premise already tested

| Rows | Expression | Reason |
|---|---|---|
| 3 | `TotpFactor:192`, `OtpFactor:299`, `RecoveryCodeFactor:190` — `RemoveEarlyReturn` on the `$userId === null` guard | Falling through runs the credential query with a null user id. Laravel rewrites `where('user_id', null)` to `where user_id is null`, and `auth_credentials.user_id` is NOT NULL, so nothing matches and the method returns `NoCredential` regardless. Same ruling as `offeredFactorsFor()`'s early return, and the premise is already pinned by *"it cannot store a credential without an owner"*. |

## Equivalent — re-derived, not inherited

| Rows | Expression | Reason |
|---|---|---|
| 1 | `OtpFactor:178` — `'secret' => null` | The column's own default; the insert is identical with or without the key. |
| 1 | `OtpFactor:391` — `InstanceOfToTrue` | Guards a branch the source documents as unreachable: the count check above already guarantees exactly one row. |
| 1 | `OtpFactor:421` — `RemoveStringCast` | PHP concatenates an int identically to its string form. |
| 1 | `TotpFactor:280` — `PlusToMinus` | The drift window is symmetric, so negating the offset maps the visited steps onto themselves. |
| 1 | `TotpFactor:283` — `ContinueToBreak` | Offsets descend, so steps descend monotonically; once one is negative every later one is, and both keywords visit the same set. |

## Prose — thrown, developer-facing (67 rows)

`TotpFactor` 63/72/81/90/128, `OtpFactor` 64/75/141/204/381,
`RecoveryCodeFactor` 68/78. Every one builds an exception message for a
misconfiguration or a programming error. Precondition re-checked at this commit,
not carried forward: `getMessage()` appears **zero** times in `src/`, so no
caller branches on message text, and the JSON surface emits only
ScreenSpec-derived keys.

**79 of 79 ruled: 2 killed, 10 equivalent, 67 prose.**
