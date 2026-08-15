# Design amendment — the ordinary recovery-code notification moves to 2.4

Amends `2026-08-12-vouch-phase-2-1-persistence-design.md`, which specified the
notification and carried it forward to 2.3.

**Decision: defer to Phase 2.4. Nothing ships in 2.3.**

## The requirement, unchanged

On ordinary use of a recovery code, notify the account:

- verified identifiers only
- post-consumption
- best-effort delivery
- **auditable**
- delivery failure must neither restore the consumed code nor disclose anything
  to the requester

## Why it cannot be built in 2.3

Two of those five words are load-bearing, and both point at things 2.3 does not
have.

### 1. "Auditable" needs a sink that deliberately does not exist yet

`AuditSink` is a contract with no binding, and that is a designed property rather
than an omission. `VouchServiceProvider` says so, and
`TenancyTest` pins it:

> it leaves AuditSink unbound so audit events cannot silently vanish —
> *drivers ship in 2.4. Until then resolving this must fail loudly: a
> silently-bound no-op would discard security events while looking healthy.*

`AuditSink`'s own docblock adds the reason the drivers cannot be hurried:
parent spec §7.6 requires a **tested redaction pass**, and that lives with the
drivers because credential material must never reach a sink.

Building the notification in 2.3 forces one of four outcomes, and all four are
worse than waiting:

| Option | Consequence |
|---|---|
| Bind a no-op sink for 2.3 | Exactly what the unbound design forbids, and the first event it would discard is *a recovery code was used* — among the highest-value audit events in the package |
| Emit no audit event | Ships a notification that fails its own specification, and creates an un-audited security-relevant delivery path |
| Resolve the sink and swallow `BindingResolutionException` | Silently unaudited, and harder to notice than the no-op |
| Resolve the sink and let it propagate | A recovery whose code is **already consumed** then fails, which breaks "delivery failure must neither restore the consumed code nor disclose anything" |

There is no fifth option that keeps the spec intact.

### 2. "Best-effort delivery" has no contract to travel on

The only delivery contract in the package is `OtpDelivery`, and it is the wrong
shape twice over:

- Its semantics are OTP-specific — `deliver(AuthIdentifier, string $code,
  DateTimeImmutable $expiresAt)` — a one-time code with an expiry. A
  recovery-use notice is neither.
- Its unconfigured driver **throws** (`UnconfiguredOtpDelivery`), by design and
  under test, because a silently-dropped OTP is an authentication failure. Route
  a *best-effort* notice through it and an unconfigured host turns the notice
  into a hard failure after the code is consumed — the same defect as option 4
  above, arriving through a different door.

So 2.3 would also have to invent a second delivery contract with opposite
failure semantics (best-effort, never fail-closed), and ship it without the audit
trail that makes "best-effort" accountable. Best-effort delivery without an audit
record is indistinguishable from no delivery at all: nothing observes the
difference.

## What 2.4 inherits

Unchanged requirement, plus the following, which this amendment fixes so the next
phase does not re-derive them:

- **Hook point.** Post-consumption means after the `FactorSatisfied` transition
  that carries the driver mutations succeeds — `AuthFlow` around the
  `$isRecovery` branch that returns `RecoveryGraceStarted`. That transition is
  the transaction whose failure must also roll back a burned code, so anything
  before it is not yet "consumed" and anything inside it is not best-effort.
- **A new contract, not `OtpDelivery`.** Best-effort semantics: an unconfigured
  or failing implementation must be a no-op that records, never a throw.
- **Audience.** Verified identifiers only — `AuthIdentifier.verified_at` is not
  null. An unverified identifier may belong to someone else.
- **Non-disclosure.** The requester's response must not change whether delivery
  succeeded, failed, or found no verified identifier. That is the same
  enumeration boundary `AuthEndpointTest` already pins for the identify step.
- **The unbound-sink test must be UPDATED, not deleted**, when the drivers land.
  It is the control that keeps a no-op sink from being bound by accident, and
  2.4 should replace "resolving throws" with "resolves to a real driver that
  records", not remove the assertion.

## What changes in 2.3

Nothing in `src/`. This amendment is the only artifact. Phase 2.3's scope is now
closed pending Task 14.

The recovery-code path itself is already complete and tested: consumption is
atomic with the transition that records the factor, `RevokeContractTest` and the
grace suite cover the surrounding behaviour, and the mutation gate rules every
surviving row in `RecoveryCodeFactor` and `GraceGuard`. What is deferred is the
*notice*, not the recovery.
