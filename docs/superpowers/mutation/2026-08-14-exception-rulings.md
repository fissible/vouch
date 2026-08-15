# Eight exception classes — 46 rows — PROSE

Each checked individually against the two disqualifying conditions, not batched
by resemblance.

| Class | Rows | Base | Caught in `src/` |
|---|---|---|---|
| `EnrollmentRefused` | 12 | `RuntimeException` | 0 |
| `SecretAlreadyRevealed` | 6 | `RuntimeException` | 0 |
| `UnknownMutation` | 6 | `LogicException` | 0 |
| `MisdirectedMutation` | 6 | `LogicException` | 0 |
| `ConflictingMutations` | 6 | `LogicException` | 0 |
| `TransitionRefused` | 4 | `RuntimeException` | **1** |
| `UnknownFlowResult` | 2 | `LogicException` | 0 |
| `ValueBoundViolation` | 4 | `InvalidArgumentException` | 0 |

**Protocol value?** No. Every row builds a message passed to
`parent::__construct()`. Nothing is stored, transmitted or compared.

**Exception class contract?** No. `getMessage()` appears in **zero** files under
`src/`. Callers match on the class and on typed properties.

`TransitionRefused` is the one caught anywhere, so it got the extra check rather
than the assumption: `DatabaseAttemptStore:90` catches it and reads
`$refused->outcome` — a typed property, not the message. Its 4 rows include a
`RemoveMethodCall` on the `parent::__construct()` call itself, which changes only
whether the message is set; the `outcome` property is assigned separately and is
what the catch consumes.

**User-visible shaped error?** No. The JSON surface emits only ScreenSpec-derived
keys, and neither `AuthFlow` nor `AuthController` catches `Throwable`.

Where an exception's *identity* carries meaning — which invariant broke, which
factor is unregistered — that is tested separately and is not the wording:
`ViolationIdentityTest`, `UnknownFactorMessageTest`, and the
`EnrollmentContentionClassifierTest` refusal reasons.

**46 of 46 ruled prose.** Manifest 294 of 364.
