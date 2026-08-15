# Two message classes the earlier passes missed — 12 rows — PROSE

Surfaced by regenerating the manifest: `src/Secrets/OneTimeSecret.php` (6 rows)
and `src/Notifications/UnconfiguredOtpDelivery.php` (6 rows) had **no ruling
document at all**. They were enumerated in the 2026-08-14 manifest and never
ruled — not disputed, simply missed, because every file-by-file pass was
organised around namespaces that did not include `Secrets` or `Notifications`.

| Site | Rows | Exception | Mutators |
|---|---|---|---|
| `OneTimeSecret:120` | 3 | `LogicException` from `__clone()` | ConcatRemoveLeft, ConcatRemoveRight, ConcatSwitchSides |
| `OneTimeSecret:136` | 3 | `LogicException` from `__set_state()` | same three |
| `UnconfiguredOtpDelivery:25` | 6 | `RuntimeException` from `deliver()` | 3× ConcatRemoveRight, 3× ConcatSwitchSides |

Classified by **dataflow**, not by mutator family, and checked against the same
three disqualifying conditions `2026-08-14-exception-rulings.md` used for its 46
rows rather than batched by resemblance to them.

**Protocol value?** No. All three sites build a message passed straight to an
exception constructor. Nothing is stored, transmitted, or compared. The literals
appear nowhere else in `src/`.

**Exception class contract?** No. `getMessage()` appears in **zero** files under
`src/` — re-verified, not inherited from the earlier pass.

**User-visible shaped error?** No, and this needed real checking rather than the
assumption, because `RuntimeException` from `deliver()` propagates out of
`OtpFactor:246` uncaught and authentication is a user-facing path. There are
exactly two catches in `src/` that could plausibly see it:

- `SessionLifecycle:55` catches `Throwable`, and re-throws
  `SessionRotationFailed::after($failure)` — the original goes in as `previous`,
  its message is never read or shaped.
- `AuthFlow:448` catches `Exception`, but its `try` wraps only
  `new DateTimeImmutable($row['satisfied_at'])` — the unparsable-timestamp guard
  — and it `continue`s, discarding the exception. Not on the delivery path.

Neither reads a message. The JSON surface still emits only ScreenSpec-derived
keys.

## The class-discrimination rule is already satisfied

The standing rule says to assert exception **messages**, not just classes, when
the class is as broad as `RuntimeException`. It is already met here, which is
worth recording because it explains why these rows survive rather than being
uncovered:

- `DeliveryFailClosedTest:26` asserts
  `toThrow(RuntimeException::class, 'No OTP delivery is configured')`. That pins
  the leading fragment, so the class cannot be confused with an unrelated
  `RuntimeException` — but Pest's message check is a *containment* test, so
  reordering or truncating the remaining fragments leaves it passing. That is
  precisely correct behaviour for prose: the discriminating part is asserted, the
  wording of the advice is not.
- `RedactionBoundaryTest` pins both `OneTimeSecret` refusals behaviourally —
  that a clone and a `var_export()` round-trip cannot produce a usable secret —
  which is the security property. The wording of the explanation is not part of
  it.

`OneTimeSecret` is the most security-sensitive file in this group, so it is worth
being explicit: the mutations touch only the **explanatory text** of two refusals.
Neither mutation can make a clone succeed, make `__set_state()` return an
instance, or reveal a value. The redaction behaviour is asserted separately and
none of these rows weakens it.

**12 of 12 ruled prose.**
