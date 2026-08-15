# ScreenBuilder and IdentifierLinkageViolation — 34 rows

The audience boundary applied explicitly, in the direction the standing rule
requires: **`ScreenBuilder` output is user-visible until proven otherwise**, and
a violation class is operator-facing only while it stays out of shaped responses.

## `ScreenBuilder` — 15 rows, line 80 — PROSE, proven

All fifteen build one `LogicException`: `Outcome::Locked` cannot be shaped in
2.3, because `ErrorShaper` discloses `Locked` in full under every posture, which
is safe only once rate limits apply identically to known and unknown
identifiers — and 2.3 ships no rate limiting.

The proof that it is not user-visible is that it **throws**, so the message
reaches a stack trace and never a response body. Asserted directly, and probed:
replacing the guard so `Locked` renders instead of throwing fails the test.

The separation is asserted as well as argued. A refusal a user *can* see carries
non-empty `errors` produced by `ErrorShaper`, containing none of the builder's
own prose — so the two audiences are genuinely distinct rather than distinct by
convention. Every other string in this class is a plain literal already pinned by
`ScreenFieldContractTest`; literals are not mutated, which is why only line 80
has survivors.

## `IdentifierLinkageViolation` — 19 rows — PROSE, precondition re-checked

Lines 29 (4), 40 (6), 50 (9): cross-user linking, unverified identifier, and a
frozen identifier already referenced by a credential.

Operator-facing, and the two conditions were re-checked rather than carried
forward at this commit:

- **Not in a shaped response.** `IdentifierLinkageViolation`,
  `ValueBoundViolation` and `ChallengeTargetViolation` are referenced **zero**
  times across `src/Http` and `src/Flow`. Nothing catches them, so nothing
  renders them.
- **Not a protocol value.** `getMessage()` appears zero times in `src/`; callers
  match on the exception class and on typed properties.

Their *identity* — which invariant each names — is separately tested by
`tests/Database/ViolationIdentityTest.php`, which is the part that carries
meaning. The wording is not.

**34 of 34 ruled: all prose, both preconditions verified at this commit.**
