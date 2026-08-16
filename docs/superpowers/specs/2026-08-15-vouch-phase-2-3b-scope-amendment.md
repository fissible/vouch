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

## Declared kernel amendment; one disclosure authority

`RetryPolicy` and `ErrorShaper` are Phase 1 kernel code and remain the sole disclosure
authority, but 2.3b deliberately amends their public surface. `RetryPolicy` gains a
nullable `DateTimeImmutable $retryAfter`. Overloading `lockedUntil` for ordinary
backoff is forbidden: it would describe an IP, tuple, tenant, or global refusal as an
account lock and violate the single identifier-lock writer.

`ErrorShaper` already decides that `Outcome::Locked` is shaped in full in every
posture, including strict. The amendment adds the corresponding ordinary-backoff
rule: under strict posture it continues to null `attemptsRemaining`, preserves a
measured `retryAfter`, and never exposes `lockedUntil` except through the identifier
lock path. Friendly posture may receive all posture-permitted fields.

This intentionally retires the blanket `src/Kernel` empty-diff property after 2.3.
Implementation must update `docs/kernel-api-surface.md`, regenerate its snapshot,
record the amendment, and mutation-test both disclosure branches. Task 14's empty
diff remains a true historical claim about completed Phase 2.3, not a promise that
later phases can never use the documented amendment process.

2.3's explicit `retry: null` is therefore not a placeholder to delete. It records
that no retry state has yet been measured. 2.3b must replace the endpoint and
strict-posture assertions with proof that a populated policy is safe for both known
and unknown identifiers. `LockoutBoundaryTest` must be rewritten at least as
strictly as its current fully-qualified-name-aware scan; it must not be removed.

A strict-posture `retryAfter` is safe only because known and nonexistent submitted
identifiers advance failure state identically. The shaper amendment and the two
equalized increment paths are one coupled invariant: changing either requires the
other's tests to fail.

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

## Counter keys, canonicalization, and operability

Throttle rows store keyed digests, never raw identifiers or IP addresses. 2.3b
extends the existing `BindingDomain` / `SessionBinding` primitive rather than
inventing a second HMAC scheme: every throttle dimension has a required, distinct
domain (`ThrottleIdentifier`, `ThrottleRecovery`, `ThrottleIp`,
`ThrottleIpIdentifier`, `ThrottleTenant`, and `ThrottleGlobal`). A caller cannot
silently derive a throttle key under a session or attempt domain.

Tenant-scoped keys require an extension of `SessionBinding` that accepts explicit,
unambiguous NUL-separated segments under one required domain. It must represent
tenant absence with a marker distinct from any present tenant value; `null` must not
flatten into the same segment as an empty-string tenant. No caller may assemble those
segments with local concatenation.

Identifiers are lowercased and normalized to Unicode NFC before derivation. Vouch
does not apply provider-specific rewriting such as Gmail dot stripping. IPv4 is
canonicalized before derivation; IPv6 is canonicalized through `inet_pton`/
`inet_ntop` and bucketed by `/64`, so textual spellings do not create separate
buckets and privacy-address rotation cannot evade the IP dimension by construction.

`APP_KEY` rotation deliberately resets throttle counters and lockouts. This is an
operator-controlled, rare bypass of the throttle, unlike session rotation where
invalidating every session is safe; it must be documented as a consequence rather
than silently inherited from `SessionBinding`'s session rationale.

Digests trade away direct operational lookup. 2.3b must not add plaintext debug or
support columns to regain it. Readable lockout/account evidence belongs in the 2.4
audit chain after its required redaction pass, not in a high-volume throttle table,
backups, replicas, or exports.

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
backoff or refuse work. They may construct only a retry policy whose measured
`retryAfter` is populated and whose `lockedUntil` is null; presenting a load-shedding
refusal as an account lockout would make both the client and the audit record lie
about the cause. Architecture tests must enforce exactly one identifier-lock writer
and forbid populated `lockedUntil` construction on every non-identifier path.

## Failure lifecycle, window, and unlock

State must be equalized wherever timing is equalized. Every failed credential
verification increments the submitted-identifier counter identically, including an
unknown user/factor path and a driver's `NoCredential` result. The two existing
`VerificationEqualizer::equalize()` call sites in `AuthFlow::verify()` are the
minimum structural anchors: a future branch may not pay the dummy hash while skipping
the state increment, or increment state while skipping the equalizer. Ordinary driver
refusals increment too. A compare-and-swap loss after the driver returned satisfied is
not a credential failure and does not charge the user for a concurrency race.

The counter row is the only stored increment: `(digest, dimension,
window_started_at, count)`. Backoff is a pure function of count, window start, and
the database clock; it is never stored separately, so it cannot drift from the fact
that produced it. Identifier lock state is a separate record containing
`locked_until`, written only by the one authorized writer when the identifier count
crosses its configured threshold.

Windows are fixed, with their start stored and rollover performed atomically in SQL.
The design accepts and documents a boundary burst of at most `2N`; thresholds must
be chosen with that property rather than described as a sliding guarantee. Window
and lock deadlines use `DatabaseTime`, and all increment/rollover/threshold behavior
requires real three-engine contention tests.

Locks are duration-bounded. Time expiry is 2.3b's documented sufficient unlock path;
there is no administrative unlock before 2.4 can make that security-relevant action
auditable. Expiry must be enforced on the request path, never by `vouch:prune`.

While a derived backoff or stored lock is active, preflight refuses before credential
verification. That refusal does not increment a counter or extend any deadline;
otherwise an attacker could maintain another user's lock indefinitely and time expiry
would not be a sufficient unlock path. The response carries the posture-shaped,
measured `retryAfter` or identifier `lockedUntil` as appropriate.

Identifier lockout does not block the explicit `action === 'recover'` path. Recovery
uses its own domain and counter, may receive bounded backoff, and remains unable to
write identifier lock state. Challenge-attempt exhaustion can still invalidate the
particular recovery challenge. This preserves a self-service escape hatch without
turning recovery into an unthrottled bypass.

Failure state resets only after full authentication. Satisfying one factor of an
`all_of` policy does not reset anything, and recovery-code acceptance starts grace
rather than authenticating the host, so it does not reset anything either. A
successful authentication may reset identifier-specific and `(IP, identifier)`
state for that subject; it never resets shared IP, tenant, global, or issuance-volume
state, because one successful account must not erase aggregate abuse.

## Security budgets and provisional defaults

The constraints below are normative; the numbers are starting defaults for
adversarial review.

OTP guessing has a multiplicative budget. With a six-digit code, challenge-attempt
cap `N = 5`, and issuance cap `M = 5`, the nominal budget is `M × N = 25` guesses
per issuance window: `25 / 10^6 = 2.5 × 10^-5`. A fixed-window boundary permits at
most twice that budget, `5 × 10^-5`. The existing 120-second OTP TTL further bounds
when each challenge can be exercised. Neither cap may be reviewed or changed without
recomputing their product and recording the target probability.

TOTP has no `auth_challenges` row and therefore no challenge-attempt backstop. With
six digits and drift window `1`, three codes are valid per 30-second step. The
identifier threshold is its sole online-guess control: ten nominal guesses give an
upper bound of `3 × 10^-5`, or `6 × 10^-5` across a fixed-window boundary before
derived backoff reduces the practical rate. The identifier threshold must never be
justified by an OTP-only challenge cap.

| Setting | Proposed global default | Constraint |
|---|---:|---|
| Identifier window | 900 seconds | Fixed window; worst-case boundary budget is `2N` |
| Backoff after | 5 failures | Must be below `lock_after` |
| Lock after | 10 failures | Only submitted-identifier dimension may lock |
| Backoff base | 2 | Exponential, derived rather than stored |
| Initial backoff | 1 second | First penalty at `backoff_after` |
| Backoff cap | 60 seconds | Must be less than or equal to the counter window |
| Lock duration | 900 seconds | Wait-out-able; administrative unlock waits for 2.4 audit |
| Challenge attempts | 5 | Per challenge; exhaustion invalidates that challenge |
| Issuances per identifier | 5 per 900 seconds | Multiplies with challenge attempts; first identify/issuance counts once |
| IP / tuple | Unresolved, higher and backoff-only | Must tolerate NAT/CGNAT; never locks an identifier |
| Tenant / global | Unresolved, high and refusal-only | Operational load shedding; never reported as account lockout |

Configuration is global in 2.3b, following the existing integer environment-backed
package config. Per-tenant tuning is deferred: tenant is a counter dimension now, not
a second configuration resolver and storage system in this phase.

Validation is relational and fail-loud. In addition to positive integer/type checks:
`backoff_after < lock_after`, `backoff_cap_seconds <= window_seconds`, and throttle
prune retention must be at least `window_seconds + lock_duration_seconds`. Lock
duration also needs an enforced v1 upper bound measured in minutes; its exact maximum,
the prune-retention default, and the IP/tuple/tenant/global thresholds remain open and
must be decided before the implementation plan. Longer operator-managed locks require
2.4's audited administrative unlock rather than a large 2.3b config value.

## Inherited mutation re-ruling

`AuthChallenge::$attempts` currently has no consumer. Its integer cast was
dispositioned equivalent only under that present fact. 2.3b gives the field its first
reader/writer for challenge caps, so the disposition is no longer inherited: the
counter's type, increments, threshold boundary, and invalidation semantics require
their own tests and mutation review.
