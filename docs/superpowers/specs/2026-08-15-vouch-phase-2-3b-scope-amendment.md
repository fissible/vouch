# Phase 2.3b/2.3c — §7.4 Scope Amendment

**Status:** Decided 2026-08-15. No implementation or new runtime contract lands in
this amendment.

## Split

§7.4 originally travelled as one item, but it combines two systems with different
authorities and inputs:

| Slice | Owns | Does not own |
|---|---|---|
| **2.3b** | Authentication throttling: limits over the submitted authentication request, exponential backoff, lockout, challenge-attempt caps, challenge-issuance volume caps, and the measured `RetryPolicy` presented by the existing flow | OTP delivery economics and CAPTCHA |
| **2.3c** | OTP delivery economics: per-tenant spend ceilings, SMS country allow-lists, daily limits, and the CAPTCHA contract | Login lockout, challenge volume, and its response disclosure |

The split keeps the strict-posture enumeration boundary with the flow that consumes
it. Challenge-issuance volume belongs beside that flow; delivery economics needs
information the current `OtpDelivery` contract does not carry — country, spend,
provider outcome, and a cost authority — so it must not be smuggled into
authentication throttling as an unexamined counter.

## Frozen 2.3 contract that 2.3b consumes

`RetryPolicy` and `ErrorShaper` are Phase 1 kernel code and remain unchanged. Their
contract already decides disclosure: `Outcome::Locked` is shaped in full in every
posture, including strict, and is safe only if known and unknown submitted
identifiers are throttled identically. 2.3b populates that existing shape; it does
not redesign it or modify `src/Kernel`.

2.3's explicit `retry: null` is therefore not a placeholder to delete. It records
that no retry state has yet been measured. 2.3b must replace the endpoint and
strict-posture assertions with proof that a populated policy is safe for both known
and unknown identifiers. `LockoutBoundaryTest` must be rewritten at least as
strictly as its current fully-qualified-name-aware scan; it must not be removed.

## CAPTCHA ladder

2.3b's escalation ladder stops at backoff and lockout. It has **no CAPTCHA rung**
and no dependency on a not-yet-defined provider contract. CAPTCHA belongs to 2.3c,
where delivery risk and provider verification can be designed together.

## Counter substrate — decided boundary, deferred shape

There is no current counter store. 2.3b owns an **authentication-specific public
contract**, not a general primitive keyed by arbitrary subjects. That narrows who can
consume the state and prevents delivery economics from becoming an accidental caller.

The mechanics are deliberately not auth-specific. 2.3b reuses `DatabaseTime` for
portable database-clock window expiry — it must call `deadlineSqlHere()` rather than
inventing interval SQL — and uses an atomic SQL increment rather than a PHP
read-modify-write. Counting in PHP lets concurrent submissions observe the same value
and all proceed, exactly the race `EnrollmentGuard` already demonstrates. The
contention-suite pattern is the required proof for the new increment.

If 2.3c needs delivery counters, it reuses those concurrency and portability
mechanics, but supplies its own delivery-facing public contract. The retrofit cost is
therefore at the surface rather than hidden in a second untested write protocol.

What is counted is decided: the enumeration-safe subject is the **submitted
identifier**, never a resolved user record. Counting only found accounts makes both
timing and lockout behaviour an account-existence oracle under strict posture.

## IP trust boundary

`AuthController` is the sole package entry point for client IP. It calls
`Request::ip()` once and passes the nullable value through `FlowRequest`; no other
package component may read forwarding headers or call `->ip()` again. Laravel's
`TrustProxies` configuration remains the host's authority: without trusted proxies,
`Request::ip()` is `REMOTE_ADDR`; with them, Laravel decides which forwarding headers
are credible. Vouch must not second-guess either choice. An architecture test must
enforce this single-entry rule, with the same namespace-qualified matching care as
the former `LockoutBoundaryTest` scan.

IP is advisory, never authentication authority. A non-null IP dimension may add
backoff, but can never create or extend an identifier lockout on its own. This is the
safe degradation under both proxy failures: under-trust collapses many users behind a
load balancer into one bucket, while over-trust permits forged forwarding headers.
When no IP is available, the IP dimension is skipped rather than sharing an
`unknown` bucket that an attacker could use for a global lockout.

This rule applies to the existing OTP challenge binding as well. `OtpFactor` may use
the captured IP as an advisory mismatch check, but it must not grant identity or
assurance, nor become a lockout authority. Its operational strength depends on the
host's proxy configuration; 2.3b documents and tests that boundary rather than
pretending IP trust was introduced by throttling.

## Counter, lockout, and pruning are separate concerns

Lockout state and counter state are separate records with separate disclosure rules.
`ErrorShaper` may disclose `lockedUntil` for `Outcome::Locked` under every posture,
but nulls `attemptsRemaining` under strict posture. Combining them into one shape
would invite callers to read and disclose both together; separate models make that
leak a deliberate violation rather than an incidental field access.

Throttle rows are high-volume, unlike `auth_enrollment_locks`. A throttle table must
be swept by `vouch:prune` under a dedicated, configured retention window; unbounded
growth is a defect. This does **not** apply to enrollment locks: those rows intentionally
persist because later PostgreSQL re-enrollment depends on `SELECT ... FOR UPDATE` after
`insertOrIgnore()` becomes a no-op. Pruning them would remove the serialization row and
break the concurrency control.

## Event table and refusal ownership

`auth_challenges.attempts` is per-challenge state. Exhausting its cap invalidates
that challenge only; it never writes identifier lock state. The driver/store mutation
that owns challenge consumption is the one writer for this transition, so no second
throttle writer may race it.

Identify and first challenge issuance are one current request: `AuthFlow` enters
`Identified` and `FactorPending` together because offering a challenge is entering
`FactorPending`. They incur one volume charge, not two. A re-issuance is distinct
only when the caller explicitly resends or switches factor; each such action is one
new issuance event.

Challenge issuance crosses both slices in a fixed order. 2.3b first permits or
refuses the event for volume, before delivery is attempted. Only after that permission
may 2.3c permit or refuse delivery for economics. One event therefore has one refusal
owner: 2.3c never re-counts volume, and 2.3b never prices delivery.

Only the submitted-identifier dimension may write identifier lock state or reach
`Outcome::Locked`. IP, `(IP, identifier)`, tenant, and global dimensions may add
backoff or refuse work, but their responses carry no populated `lockedUntil` or
identifier `RetryPolicy`; presenting a load-shedding refusal as an account lockout
would make both the client and the audit record lie about the cause. Architecture
tests must enforce exactly one identifier-lock writer and forbid populated
`lockedUntil` construction on every non-identifier path.

## Inherited mutation re-ruling

`AuthChallenge::$attempts` currently has no consumer. Its integer cast was
dispositioned equivalent only under that present fact. 2.3b gives the field its first
reader/writer for challenge caps, so the disposition is no longer inherited: the
counter's type, increments, threshold boundary, and invalidation semantics require
their own tests and mutation review.
