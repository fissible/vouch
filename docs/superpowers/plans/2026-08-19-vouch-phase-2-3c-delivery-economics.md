# Phase 2.3c — OTP delivery economics and CAPTCHA

## Goal

Complete the delivery-economics boundary reserved by `ChallengeIssuer`:

- SMS country allow-lists;
- per-tenant spend ceilings;
- daily spend limits;
- a provider-independent CAPTCHA contract;
- adversarial tests proving that economics can refuse delivery without
  recounting authentication volume or reaching an OTP factor.

2.3c does not redesign authentication throttling. Volume permission remains the
2.3b decision and runs first. The 2.3c decision runs only after a server-owned
target has been selected and immediately before the factor challenge call.

## Non-negotiable boundaries

1. `ChallengeIssuer` remains the sole production caller of `Factor::challenge()`.
2. Economics receives delivery metadata, never a resolved user as its policy key.
3. A refusal is target-independent in its externally visible shape and never
   refunds or re-counts the 2.3b issuance event.
4. The CAPTCHA contract is verification-only: no provider, token secret, or
   challenge implementation ships in this phase.
5. SMS country is derived from the verified identifier target; email delivery
   does not enter the SMS country policy.
6. Spend accounting is delivery-facing state and is separate from authentication
   issuance volume. It must not be used as a substitute for the 2.3b counter.
7. No synchronous provider work is introduced. Economics must complete before
   the existing encrypted outbox path and cannot make the request path contact
   a provider.

## Resolutions added before source work

### Decoys and spend

The request path does **not** charge delivery spend. `ChallengeIssuer` performs
only a read-only, target-independent economics preflight after 2.3b volume
permission. It may reject a globally disabled delivery mode, but it cannot make
country- or target-dependent spend decisions there.

The encrypted outbox worker performs the delivery-facing decision for a real
target: country allow-list, tenant/daily ceiling, and the atomic spend
reservation immediately before provider work. A decoy outbox is deleted without
provider contact and without spend accounting. Because the worker is after the
response, real/decoy request timing and refusal shape remain identical, while
unknown identifiers cannot pollute a tenant's spend ceiling. Authentication
issuance volume is never refunded or rewritten; delivery-spend reservations are
a separate ledger and may be released only under the provider outcome contract.

The request-side check is advisory fast-fail only. The worker reservation is the
authoritative check-and-act operation and must enforce the ceiling in its atomic
SQL predicate; a burst that passes the advisory read cannot overspend merely
because several workers arrive together.

This deliberately means an economics refusal at worker time does not reach the
factor's provider call, but the factor may still create the already-encrypted
outbox record. The request-side preflight and the worker-side decision are two
parts of one named boundary, not two independent policy owners.

Worker economics refusal is a distinct redacted terminal state from
expired-undelivered. The former means the delivery budget refused an otherwise
live attempt; the latter is evidence of a stale or dead worker. Prune and
aggregate reporting count them separately, and only the latter contributes to
the delivery-health alert/exit signal.

The outbox lifecycle remains deliberately small (`pending`, `delivered`,
`undeliverable`); terminal causes are recorded beside it in `failure_reason`,
not added as enum cases. Reasons distinguish legacy-unparseable targets,
country policy refusal, spend-ceiling refusal, provider rejection/exhaustion,
expired-undelivered work, and unavailable targets. This keeps lifecycle queries
stable while making aggregate operations actionable: migration work, policy
review, budget review, provider investigation, and queue-health alerting are
separate counts. Worker-time terminalization is silent to the user, so the
reason is retained and reported without exposing a target or code.

The worker's encounter counts complement, rather than replace, the aggregate
SMS audit. The audit measures the stored population; terminal reasons measure
which legacy or policy conditions are actually encountered by users. Missing
outbox rows after TTL are a no-op success for the worker, while an expired row
that was never delivered is retained as `expired_undelivered` for queue-health
reporting. Spend refusals are a separate terminal reason and must not be
collapsed into that health signal.

### Worker reservation contract

The encrypted outbox payload remains exactly `{target, code, decoy}`. Tenant and
factor are stable relational facts: a deliverable outbox row implies a live
challenge and attempt through cascading foreign keys, so the worker joins
`auth_challenges.factor_type` to `auth_attempts.tenant_id`. Country is derived
from the snapshotted target with `SmsCountryNormalizer`; it is not persisted as
a second copy of that fact. Delivery cost is live policy and is read from the
bound economics configuration at reservation time, not frozen into queued work.

`reserve()` needs a result richer than the advisory preflight's boolean-shaped
decision. Its typed outcomes are: permitted, permanently refused because the
country is not allowed, permanently refused because the ceiling is exhausted,
and retryable contention. Only the first three terminalize an outbox row;
contention leaves it pending and lets the queue retry. The existing
`LegacyUnparseable` failure reason remains valid for legacy targets that fail
worker-time normalization; it must be assigned by the worker or removed before
the lifecycle ships, never left as an unreferenced enum case.

Queue exhaustion must preserve that distinction too: a job exhausted by
economics contention has not contacted a provider and must not be recorded as
`provider_exhausted`. Contention retries also do not consume the provider
delivery-attempt budget. The worker may retry the reservation in the same job
attempt, or the queue integration must carry a separate contention budget;
using one undifferentiated `$tries` counter is not evidence that either policy
is correct.

`release()` is not a separate budget: database, Redis, and SQS drivers all
advance their receive/attempt count when a released job is delivered again.
The chosen shape is a bounded in-attempt reservation retry followed, if needed,
by dispatching a fresh `DeliverOtpChallenge` with a delay. The row remains
pending; expiry is the final boundary and terminalizes as
`expired_undelivered`. Queue behavior is verified with a real database queue,
including the attempt count after release, rather than inferred from a fake.

The reservation call sits outside the provider-I/O `try` block. A vanished
spend row, unsupported configuration, or other storage failure must remain a
storage/configuration error; it must not be wrapped as
`TransientOtpDeliveryFailure`, labeled `provider_exhausted`, or retried as if a
provider had been contacted.

Reservation is idempotent per `AuthChallengeOutbox::opaque_id`. The worker
reserves before provider I/O, but a transient provider failure leaves the row
pending and the next attempt must not increment spend again. A reservation
ledger keyed by opaque id and spend scope records the successful reservation in
the same transaction as the aggregate increment; retries detect the existing
reservation and skip the increment. This is a charge-per-send decision, not a
charge-per-provider-attempt decision.

The reservation ledger enforces uniqueness with a database constraint on
`(opaque_id, scope)`, not a read-then-write check. Two workers may select the
same pending outbox row concurrently and both may reach reservation; a
`tests/Concurrency/` race must prove that `spent_minor` advances once even
though duplicate provider delivery remains an accepted posture. Per-scope
keying is required because live configuration can add a scope between retries;
an opaque-id-only key would silently skip the newly configured scope.

The configuration surface is part of this slice. `DeliveryEconomicsConfiguration`
is container-bound and validates ceilings plus live cost policy: a per-channel
cost is required, with optional per-country SMS overrides for providers whose
pricing differs by destination. No cost is silently defaulted to zero for a
real delivery.

### Accounting is independent of enforcement

Spend accounting is not conditional on whether a ceiling is armed. Every
permitted, real, priced delivery records both the global and tenant scopes
(with the existing explicit absent-tenant digest); a configured ceiling adds an
atomic refusal predicate to that scope, but does not determine whether the row
exists. This makes aggregate reporting a statement about delivered economics,
not a partial view whose coverage changes when an operator toggles enforcement.
The cost is one locked aggregate update per scope even in observe mode, which
is accepted as the price of complete reporting. Decoys and zero-cost deliveries
do not create spend rows.

The atomic update must keep enforcement diagnosis separate from write health:
an armed ceiling adds the `spent_minor <= ceiling - cost` predicate, so zero
affected rows there means `SpendCeiling`; an unarmed scope increments without
that predicate, and zero affected rows then means the row vanished after its
lock and must raise a storage error. Since every priced delivery now records
these scopes, contention and bounded-wait behavior are part of the common
observe-mode path, not only of ceiling-enforcing installations.

### CAPTCHA communication and ordering

CAPTCHA requirement is a kernel disclosure decision, not an ad hoc response
field. 2.3c will amend `RetryPolicy`/`ScreenSpec` through the documented kernel
API process and update the API snapshot. The challenge metadata is nullable and
only populated from shared/volume state; identifier-specific state may never
make one submitted identifier receive a CAPTCHA while another does not.

The ordering is explicit:

1. 2.3b volume preflight;
2. hard economics eligibility that cannot be unlocked by CAPTCHA (for example,
   a disallowed SMS country);
3. CAPTCHA verification when the shared/volume policy requires it;
4. final delivery-spend reservation and outbox/provider lifecycle.

Thus a user is not asked to solve a CAPTCHA for a destination that is forbidden
anyway, while a CAPTCHA can satisfy only the shared-volume gate it is designed
to remedy. CAPTCHA never bypasses a country allow-list or a hard spend ceiling.

### SMS country input

SMS numbers are parsed with `giggsey/libphonenumber-for-php`, not a prefix table.
Enrollment normalizes valid numbers to canonical E.164 and records the ISO
country used by economics; unparseable or ambiguous numbers fail closed before
an SMS credential can be enrolled or delivered. Existing non-canonical rows are
not guessed at send time: they require re-enrollment or an explicit migration;
legacy rows that remain unparseable fail closed at the worker boundary and never
contact a provider.

### Style and reconciliation gates

Pint is not currently a dependency of this package. The 2.3c gate therefore
does not claim Pint cleanliness: PHPStan, `git diff --check`, and the three-engine
tests are mandatory. If the package adopts Pint later, adding the dependency and
running it becomes a separate explicit gate rather than an `if available` step.

Every new locking or spend expression receives a row-level mutation ruling.
Shared matrix prose is not evidence: a row is matrix-required only when the
specific engine behavior can discriminate that expression, and constructor or
configuration rows get deterministic tests instead.

The `insertOrIgnore`-then-`lockForUpdate` sequence is a named concurrency gate,
not evidence by itself. It has two materially different paths: an absent row,
where the insert serializes, and a committed row, where PostgreSQL's
`insertOrIgnore` is a no-op and `lockForUpdate` is the only serializer. SQLite
does not expose the latter lock. Delivery-spend code must use the shared
lock/ensure primitive once extracted from the existing enrollment and throttle
implementations, and its matrix must include both paths. A file-backed SQLite
race is necessary for liveness but cannot certify that the row lock is
load-bearing; the discriminating probe is the same mutation with the lock
removed, failing on PostgreSQL while SQLite remains green.

The CI database-matrix job installs `pcntl` because the two-process race must run
there. The ordinary in-memory SQLite job may still skip it, but that skip is not
evidence and cannot be the only execution of the test.

## Dependency order

### 1. Contracts and immutable intents

- Add a delivery-economics contract with an immutable target-bearing intent.
- Add a typed decision/result that distinguishes permitted delivery from an
  economics refusal without nullable combinations.
- Add a CAPTCHA verifier contract with an immutable verification request/result.
- Add an explicit unconfigured implementation that fails closed; do not bind a
  permissive no-op.
- Extend `ChallengeIssuer` at the existing named boundary only.

Focused proofs:

- economics refusal reaches no factor and leaves the issuance counter unchanged;
- permitted economics reaches exactly one factor challenge;
- missing economics binding fails before provider work;
- CAPTCHA is never called for non-escalated delivery and a failed verification
  cannot be treated as success.

### 2. Delivery metadata and canonical policy inputs

- Carry channel, verified identifier type/value metadata, tenant identity, and
  configured delivery cost in the intent.
- Normalize SMS country through one canonical parser boundary; do not infer it
  from arbitrary request headers or a second IP/proxy lookup.
- Keep tenant absence distinct from an empty tenant identifier.
- Before changing enrollment or stored values, provide an aggregate
  `vouch:sms-identifiers:audit` report classifying canonical, needs-normalization,
  and invalid legacy rows. The report emits counts and country aggregates only;
  it never rewrites rows or prints identifier values. It accepts no subject
  lookup input and exits `0` for a survey containing invalid rows; only an
  audit execution error is a command failure.

The migration decision is population-dependent and remains open until this
command runs against a deployment dataset. Test fixtures are not evidence for
that decision. The recorded rule is:

| Audit result | Migration posture |
| --- | --- |
| `invalid = 0` | A normalization backfill is possible; verify matching/index effects before applying it. |
| `invalid` is small | Handle the counted rows through explicit re-enrollment/contact; do not silently rewrite them. |
| `invalid` is large | Do not ship a mass fail-closed send rule; use a staged re-enrollment plan. |
| `needs_normalization` is small | Review whether a routine backfill preserves account matching, then apply with a report. |
| `needs_normalization` is large | Treat the rewrite as a compatibility/communication change, not maintenance. |

No production population has been measured in this repository. Until an
operator supplies that aggregate report, legacy rows remain unchanged and the
worker's fail-closed behavior is the safety boundary.

### 3. Economic state and atomic decisions

- Add delivery-facing persistence for daily/tenant spend and country decisions.
- Use database-clock deadlines and atomic SQL updates/inserts; no PHP
  read-modify-write.
- Prove same/different tenant and same/different country contention on all three
  engines where the database semantics matter.
- Keep delivery accounting independent from authentication-volume transactions;
  under failure, under-counting is safer than collateral over-counting.

### 4. CAPTCHA integration

- Define the escalation point without adding a 2.3b CAPTCHA rung retroactively.
- Verify CAPTCHA before a delivery is permitted, after volume permission and
  before the factor call.
- Preserve strict-posture response shape and never expose provider diagnostics or
  account existence through CAPTCHA refusal.
- Add architecture coverage preventing a direct provider/CAPTCHA call from the
  flow or factor drivers.

### 5. Operational reporting and reconciliation

- Extend aggregate reporting without emitting identifiers, addresses, candidate
  lookup inputs, or provider secrets.
- Update prune retention for delivery-economic state separately from OTP payload
  retention and throttle state.
- Re-run the three-engine suite, PHPStan, `git diff --check`, and the mutation
  manifest for all new source expressions. Pint is not a package gate unless it
  becomes an explicit dependency.

## Validation labeling

Every reported test count must name its execution configuration. The ordinary
in-memory SQLite gate skips the 25 contention tests; file-backed SQLite runs
those same tests. Therefore `1,088 passed / 25 skipped` and `1,113 passed / 0
skipped` are the same 1,113-test collection, not competing regressions.

Local concurrency evidence uses file-backed SQLite. Cross-engine evidence names
the MySQL and PostgreSQL versions and ports. A bare test count is not a
comparable metric and must not appear in a 2.3c report without its engine and
SQLite mode.

## First implementation slice

The first commit should contain only the contracts, unconfigured fail-closed
implementations, the issuer seam, and focused tests. It must not add a permissive
default or persistence whose policy has not yet been exercised.
