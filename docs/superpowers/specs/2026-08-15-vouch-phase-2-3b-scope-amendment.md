# Phase 2.3b/2.3c — §7.4 Scope Amendment

**Status:** Core throttling design complete 2026-08-15; Task 14's transport lifecycle
is an explicit pre-implementation design gate. No implementation or new runtime
contract lands in this amendment. Dependency-ordered implementation plan:
[`../plans/2026-08-15-vouch-phase-2-3b-auth-throttling.md`](../plans/2026-08-15-vouch-phase-2-3b-auth-throttling.md).

## Split

§7.4 originally travelled as one item, but it combines two systems with different
authorities and inputs:

| Slice | Owns | Does not own |
|---|---|---|
| **2.3b** | Corrective production issuance integration for email/SMS OTP, plus authentication throttling: limits over the submitted authentication request, exponential backoff, lockout, challenge-attempt caps, challenge-issuance volume caps, and the measured `RetryPolicy` presented by the existing flow | OTP delivery economics and CAPTCHA |
| **2.3c** | OTP delivery economics: per-tenant spend ceilings, SMS country allow-lists, daily limits, and the CAPTCHA contract | Login lockout, challenge volume, and its response disclosure |

The split keeps the strict-posture enumeration boundary with the flow that consumes
it. Challenge-issuance volume belongs beside that flow; delivery economics needs
information the current `OtpDelivery` contract does not carry — country, spend,
provider outcome, and a cost authority — so it must not be smuggled into
authentication throttling as an unexamined counter.

## Cross-phase correctness repair and delivery-economics seam

2.3b is not controls-only. A post-certification source trace found that nothing in
`src/` calls `Factor::challenge()`. `AuthFlow`'s four similarly named calls all target
`ScreenBuilder`; `OtpFactor::challenge()` is the only path that creates an
`auth_challenges` row and calls `OtpDelivery::deliver()`, and all of its callers are
tests. Email/SMS OTP is therefore not end-to-end functional through the shipped flow,
despite both drivers being registered and `config/vouch.php` advertising them in
`challenges.require_credential`.

Task 14 is a Phase 2.3 correctness repair and a Phase 2.3b control boundary. It
introduces a dedicated `ChallengeIssuer`, enforced as the sole owner of production
challenge issuance. `AuthFlow`, controllers, and future delivery policy never call a
factor or `OtpDelivery` directly. The issuer's pipeline is fixed:

1. Construct an immutable, target-free issuance-attempt intent from the canonical
   submitted identifier, action, and factor id carried by posture-safe flow state.
   This resolves no user or credential and creates no code, challenge row, or delivery
   side effect.
2. Atomically charge/permit the 2.3b issuance-volume event. Known and nonexistent
   identifiers—including explicit resend—advance the same state and reach refusal on
   the same request. A missing target never skips or refunds this charge.
3. Resolve the server-owned real target or construct the posture-safe decoy state.
4. For a real delivery, cross the single named insertion point where 2.3c will later
   require its delivery-economics authority.
5. Only after every applicable authority permits may the issuer invoke the selected
   challenge implementation.

2.3b does not bind a fake or permissive economics implementation: that would make an
absent 2.3c control look installed. Instead, the typed issuance intent and the single
issuer make the future insertion structural and local; 2.3c adds its required contract
at step 4. A volume refusal reaches neither that future authority nor the driver. When
2.3c exists, an economics refusal likewise reaches no driver, and 2.3c never recounts
volume. Architecture tests must keep `ChallengeIssuer` as the sole production call
site, and end-to-end tests must prove both email and SMS produce a stored challenge,
invoke the configured transport, and can complete verification through the HTTP flow.

### Open Task 14 design gate — request timing and partial issuance

The current `OtpFactor::challenge()` is synchronous. It calls
`AuthChallenge::create()` and then `OtpDelivery::deliver()` on the request path; there
is no queue, outbox, or transaction around the pair. Wiring that method into
`ChallengeIssuer` unchanged would introduce two failures:

- Real SMTP/SMS latency would make a resolved target observably slower than an unknown
  target whose decoy sends nothing. Uniform status/body and verification equalization
  do not close that request-time channel.
- A delivery exception occurs after the challenge row committed and after the
  target-independent issuance charge. A provider outage can therefore leave an
  unusable live challenge and consume a legitimate user's allowance.

A decoy cannot close the synchronous-send timing gap. It can reproduce target
resolution and local persistence work, but the real branch then performs a network
round trip that the decoy branch cannot safely copy. Skipping it preserves the timing
signal; sending a dummy message to attacker-influenced input creates the mail/SMS
amplifier §7.1 explicitly forbids. Durable request-path isolation is therefore a
requirement, not one candidate to weigh against synchronous alternatives.

A local database transaction is not, by itself, a resolution. It can roll back the
row when delivery throws, but it cannot atomically commit an external provider side
effect: delivery can succeed and the database commit can then fail, producing a sent
code with no verifiable row.

The durable boundary is a package-owned delivery outbox. The request transaction may
atomically create the challenge row and its outbox record, then return without making
an external call; no database transaction is held across provider I/O. Real and decoy
issuance must perform the same request-side durable work shape. A worker handles the
real transport later, while a decoy is discarded without contacting a provider. A
Laravel `sync` queue driver or equivalent inline executor must be rejected, not
silently accepted as “queued.”

At-least-once delivery makes the outbox payload live credential material. The worker
must resend the exact code already hashed into `auth_challenges`; re-invoking the
driver would mint a replacement and invalidate a code that may already have reached
the user. The outbox therefore stores the code plus target/message metadata encrypted
at rest. A queued job carries only an opaque outbox id—never the code, target, or
serialized payload—so plaintext cannot migrate into queue tables, failed-job records,
logs, or support exports. The model hides the encrypted attribute from array/JSON
serialization, and tests read the raw database value to prove plaintext is absent.

Outbox expiry is the challenge's own `expires_at` (120 seconds with current OTP
defaults), never the throttle table's 86400-second retention. Workers refuse expired
rows at that exact deadline and cleanup removes them on the next scheduled sweep;
retry/backoff cannot extend a code's validity. Rotation or loss of the encryption key
fails closed—there is no plaintext fallback—and the row expires normally.

The redacted row state distinguishes `pending`, `delivered`, and `undeliverable`;
status and timestamps contain no target or credential material. On successful
provider acceptance the worker clears the encrypted payload immediately and marks
`delivered`. A transient failure may retain the payload only while `database_now <
expires_at`. A permanent failure, or a worker observing expiry, clears the payload and
marks `undeliverable` without retry. The redacted row remains until cleanup so the
operational signal is not erased by the component that first notices it.

An opaque job id that no longer resolves is a normal idempotent terminal outcome. The
row may already have been delivered and swept, expired and swept, or finalized by
another worker. The handler returns success and schedules no retry; it must not create
failed-job noise or a retry storm from an ordinary queue backlog. A present but
expired row takes the same no-retry path after clearing its payload and recording
`undeliverable`.

Cleanup classifies before deletion. It reports delivered-expired and
expired-undelivered counts separately, placing every expired row not marked delivered
in the latter class. It emits a warning containing that aggregate undelivered count
and returns status `2` when the count is positive. Exit statuses have exactly one
meaning each: `0` means the sweep succeeded with no undelivered finding, `1` means the
sweep itself failed, and `2` means the sweep succeeded and found expired undelivered
work. In particular, status `2` does not imply any attempt/session/outbox deletion was
rolled back or skipped. Monitoring must route `2` to delivery-worker health while
reserving `1` for the prune operation and its owner. Collapsing either condition into
generic non-zero failure is forbidden; it recreates the ambiguous-success failure the
mutation gate already records for a child process whose exit `0` meant both "tests
passed" and "no tests ran." This is the package's available dead-worker signal before
2.4 supplies an auditable sink. Deleting both classes silently is forbidden.
`vouch:throttle:report` also exposes aggregate current pending, overdue, delivered,
and undeliverable outbox health, with no subject rows or candidate-lookup input. The
prune command's own output/status is the durable operational signal for rows it
removes; the report does not invent historical delivery telemetry after deletion.

The package must register/document the cleanup cadence and require the host scheduler
to run it at least once per minute. Enforcement remains exact at `expires_at`: workers
cannot deliver or decrypt for transport after the deadline. Physical deletion occurs
on the next sweep, so maximum retained ciphertext is the 120-second OTP TTL plus one
documented sweep interval—not the 24-hour throttle retention. A missing scheduler is
still host infrastructure the request cannot observe; the installation/health
documentation must name that dependency rather than implying outbox insertion proves
delivery is healthy.

### Scheduling `vouch:prune`

Laravel's scheduler treats every non-zero command exit as task failure, and
`->onFailure()` therefore cannot distinguish status `1` from status `2`. Scheduling
`Schedule::command('vouch:prune')->onFailure(...)` is forbidden for this contract: it
routes a successful sweep with a delivery-health finding to the prune-failure owner,
and repeated worker incidents train operators to ignore the same channel a real prune
failure later needs.

Hosts must preserve the distinction with a scheduled callback that reads the command
status itself. The warning channel below is deliberately host-owned; configure or
substitute the application's delivery-health integration:

```php
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schedule;

Schedule::call(function (): void {
    $status = Artisan::call('vouch:prune');

    if ($status === 2) {
        Log::warning('Vouch found expired undelivered OTP work.', [
            'aggregate' => Artisan::output(),
        ]);

        return;
    }

    if ($status !== 0) {
        throw new \RuntimeException("vouch:prune failed with status {$status}");
    }
})->everyMinute()->name('vouch:prune');
```

The wrapper completes successfully for statuses `0` and `2`; only prune failure or an
unknown contract value fails the scheduled task. Configure the warning channel—or
replace it with the host's delivery-health integration—to page the worker owner. The
status-`2` alert consumes only the aggregate output defined above. It may not add
subject-level lookup or payload data while adapting the signal.

Task 14 must still add a narrow amendment before source work settles the remaining
lifecycle choices: how a durable worker is dispatched/recovered; when a challenge
becomes verifiable; how an already pending issuance coalesces explicit resends; and
how unconfigured delivery fails visibly to the host without becoming a public
existence signal. The amendment must state the unavoidable at-least-once
duplicate-delivery risk rather than claiming exactly-once provider behavior.

Two constraints survive every choice. The authentication issuance-volume charge is
target-independent and is never refunded/skipped based on resolution or provider
outcome; otherwise the counter becomes an existence oracle. Transport retries for one
accepted issuance are not new authentication issuance events. Avoiding collateral
budget burn during an outage must therefore come from the chosen delivery/retry/
coalescing lifecycle, not from a target-dependent counter correction.

“Issuance volume” therefore means admitted **issuance-attempt events**, not successful
provider deliveries. 2.3c may separately account for actual delivery/spend, but it may
not rewrite the authentication-volume record. Target resolution and the future
economics decision also inherit the request-path timing constraint: work performed
only for a real target cannot remain synchronously observable before the response.

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
contention-suite pattern is the required proof for the new increment and for the
distinct-tuple accounting described below. A denormalized distinct count based on
`insertOrIgnore()`'s affected-row result is deliberately rejected: that result is an
engine/driver contract, and this project has already disproved two similarly assumed
cross-engine premises. Correctness must not depend on it without a separate
three-engine measurement.

Lock-wait bounding and verified contention classification are shared database
mechanics, not copied auth policy. 2.3b extracts the per-driver behavior already
proved by `EnrollmentGuard` into one internal primitive, parameterized by the caller's
wait budget and failure policy. The extraction must preserve EnrollmentGuard's
fail-closed refusal while allowing the advisory shared-throttle path to fail open as
defined below. Unknown drivers and unclassified query errors fail loudly.

The extracted primitive also closes a side effect that is tolerable only because
enrollment is rare: PostgreSQL's `SET LOCAL` is transaction-scoped, but MySQL's
`innodb_lock_wait_timeout` and SQLite's `PRAGMA busy_timeout` persist on a reused
connection. Throttling runs on every failed verification, so it must read the prior
setting and restore it in `finally` on success, contention, and unrelated exception
paths. Long-lived-worker tests must prove that vouch leaves the host connection's
setting unchanged.

Adopting the primitive in `EnrollmentGuard` is a declared correction to Phase 2.1
behavior, not an incidental refactor. The guard's pre-2.3b `KNOWN SIDE EFFECT`
docblock documented a real leak: one enrollment lowered the lock tolerance for
unrelated future queries on a pooled connection. Task 3 removes that leak and makes
the guard use the same restoring primitive as throttling.
Keeping a restoring throttle helper beside a leaking enrollment implementation would
create two meanings for the same database concern.

The prior value is captured for every invocation and restoration never means resetting
to an engine default. MySQL and SQLite restore explicitly in `finally`. PostgreSQL's
bound is transaction-local: normal and nested exits restore explicitly, while a
statement failure aborts the transaction and makes restoration SQL fail with `25P02`.
In that one measured case the primitive preserves the original query exception and
rollback performs the guaranteed restoration. Per-call capture makes nesting compose:
if the host value is `H`, an outer throttle scope sets `1`, and a nested enrollment
scope sets `5`, enrollment restores `1` before throttle restores `H`. MySQL reads the
prior value from `@@SESSION.innodb_lock_wait_timeout`, SQLite from bare
`PRAGMA busy_timeout`, and PostgreSQL from its current `lock_timeout` setting. Tests
must cover success, classified contention, unrelated exceptions, and nesting on every
engine.

The existing enrollment contention assertion must be split rather than weakened. Its
post-contention MySQL/SQLite readback currently proves the bound was applied precisely
because those settings leak; restoration will correctly make that assertion fail.
The internal primitive therefore gets a direct test that reads the bounded value from
inside its critical section and the prior value after exit, while
`EnrollmentContentionTest` retains the real held-lock liveness/refusal assertion. The
two proofs remain separate and both load-bearing: elapsed time alone is vacuous on
SQLite, whose unbounded default is to fail immediately, while setting readback alone
does not prove a contended request returns.

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

IPv4-address and IPv6-`/64` buckets are distinct configuration dimensions, not two
encodings of one limit. An IPv6 `/64` is commonly one subscriber, while one public
IPv4 address behind NAT or CGNAT may represent thousands of unrelated users. Applying
one threshold to both would systematically give the IPv4 path the larger collateral
denial surface. Both remain backoff-only, but IPv4 therefore requires a more generous
threshold than IPv6 `/64`, and both backoff caps remain measured in seconds rather
than minutes so an advisory shared bucket cannot become a lockout in effect.

This rule applies to the existing OTP challenge binding as well. `OtpFactor` may use
the captured IP as an advisory mismatch check, but it must not grant identity or
assurance, nor become a lockout authority. Its operational strength depends on the
host's proxy configuration; 2.3b documents and tests that boundary rather than
pretending IP trust was introduced by throttling.

## Counter keys, canonicalization, and operability

Throttle rows store keyed digests, never raw identifiers or IP addresses. 2.3b
extends the existing `BindingDomain` / `SessionBinding` primitive rather than
inventing a second HMAC scheme: every throttle dimension has a required, distinct
domain (`ThrottleIdentifier`, `ThrottleRecovery`, `ThrottleIssuance`,
`ThrottleIpV4`, `ThrottleIpV6`, `ThrottleIpIdentifier`, `ThrottleTenant`, and
`ThrottleGlobal`). A
caller cannot silently derive a throttle key under a session or attempt domain, and
the two IP families cannot accidentally consume one another's threshold.

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
An IPv4-mapped IPv6 value canonicalizes to its underlying IPv4 subject; treating it
as native IPv6 would collapse every mapped IPv4 client into the same `::/64` bucket.

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

Throttle rows are high-volume, unlike `auth_enrollment_locks`. Scalar counter and
lock rows must be swept by `vouch:prune` under the dedicated, configured retention
window; unbounded growth is a defect. This does **not** apply to enrollment locks:
those rows intentionally persist because later PostgreSQL re-enrollment depends on
`SELECT ... FOR UPDATE` after `insertOrIgnore()` becomes a no-op. Pruning them would
remove the serialization row and break the concurrency control.

Tuple markers have a shorter lifetime than scalar counters and lock records. They
carry no lock state and exist only to define one IP window's distinct-identifier set,
so `vouch:prune` removes them as soon as that database-clock window has completed.
Their retention is derived from `window_seconds`, not copied into a second config key;
derivation prevents the largest attacker-growable table from silently inheriting the
86400-second scalar-row retention or drifting away from the window it serves. The
active parent/window predicate, prune predicate, and exact-boundary behavior require
the same three-engine `DatabaseTime` proof as counter rollover.

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

Scalar counter rows store `(digest, dimension, window_started_at, count)`. Backoff is
a pure function of count, window start, and the database clock; it is never stored
separately, so it cannot drift from the fact that produced it. Identifier lock state
is a separate record containing `locked_until`, written only by the one authorized
writer when the identifier count crosses its configured threshold.

The backoff deadline is cumulative from the fixed-window start. For count `c` at or
above `backoff_after = A`, its offset is
`sum(i = 0 .. c-A, min(initial * base^i, cap))`; `retryAfter` is the earlier of
`window_started_at + offset` and the window deadline. Counts below `A` have no
backoff. If database `now` has already passed that deadline, preflight permits work.
With defaults this yields offsets 1, 3, 7, 15, and 31 seconds at counts 5–9; count 10
locks instead. This is burst backoff rather than a stored “last failure + delay” clock:
the latter would require another timestamp and contradict the decided row shape.

The `(IP, identifier)` tuple is not a second failure counter and has no independent
refusal threshold. A proposed threshold of 20 is unreachable: the identifier locks
at 10, and active backoff or lock refusals do not increment either subject. Putting
the tuple threshold at or below 10 would instead let a refusal-only dimension preempt
the only writer authorized to lock. Storage without a reachable decision is not a
control.

The tuple therefore supplies the denominator the raw IP count lacks. For each IP
window, the first failed verification for a canonical `(IP, submitted identifier)`
creates a unique tuple marker; repeated failures for the same tuple do not add another.
One address failing twenty times against one identifier contributes one distinct
subject, while one address probing twenty identifiers contributes twenty. The active
IP value is an indexed `COUNT` of those markers, not a denormalized integer.

The derived count still needs serialization. The transaction ensures an IP-window
parent row exists, locks that row, atomically rolls its database-clock window when
needed, creates the marker if absent, and then counts the markers for that exact parent
and window. The parent lock makes concurrent first markers visible in one order rather
than letting two transactions each decide against a partial set. PostgreSQL and MySQL
must prove the row lock under real two-connection contention; SQLite must prove the
same result under its global writer behavior. Tests must cover two concurrent failures
for the same tuple counting once and two distinct tuples counting twice. No assertion
may infer this from a query-builder return value.

A successful login does not delete the marker: doing so would let one valid account
erase or repeatedly re-add IP-spread evidence.

The contention matrix must distinguish the paths that serialize for different
reasons. At minimum it crosses `{same tuple, distinct tuple}` with `{parent absent,
parent already committed}` on SQLite, MySQL, and PostgreSQL. The absent-parent insert
serializes on all three engines; it cannot prove the committed-parent path, where
PostgreSQL's no-op `insertOrIgnore()` takes no lock and `lockForUpdate()` is the only
serializer. Two further exact-boundary cases cross same/distinct tuples with a
committed but expired parent, proving rollover creates one new window, excludes old
markers, and does not double-count. A matrix that exercises only first insertion is
vacuous for the production path, just as the original enrollment contention suite was.

Parent-lock acquisition is bounded to one second, the smallest portable MySQL wait
unit. It is not configurable upward in 2.3b: an advisory counter must not park a
request thread behind the busiest CGNAT bucket long enough to become the denial it is
meant to mitigate. PostgreSQL, MySQL, and SQLite must each prove the bound using the
real held-lock path and the verified driver-specific contention code; wall-clock-only
assertions are insufficient.

If that wait expires, vouch skips the contended shared IP/tuple observation and
enforcement for this request, then continues through the submitted-identifier
dimension. The same policy applies to a verified contention timeout on tenant or
global counter state: all non-identifier dimensions are shared and advisory. The
failure is deliberately open only for that dimension; the identifier counter still
advances identically for known and nonexistent subjects and remains the sole lock
authority. The timeout emits no `lockedUntil`, no shared refusal, and no invented
retry state. Swallowing every `QueryException` would turn a missing table or bad column
into an invisible throttle bypass, so only measured lock/busy codes receive this
degradation; every other database error propagates unchanged.

The advisory attempt and authoritative identifier update cannot share a transaction.
PostgreSQL marks a transaction failed after `lock_timeout`; catching the exception
inside that transaction and then trying to count the identifier would not preserve the
control. After a failed credential verification, the authoritative identifier update
commits first. The advisory shared update then runs in its own transaction; if its wait
expires, that transaction rolls back and its connection setting is restored. A held
shared-parent lock must prove end to end on every engine that the request returns
within the bound, no tuple marker or shared count is written, and the identifier count
nevertheless advances to lock at the ordinary threshold. This assertion is the
evidence for fail-open degradation; a returned response alone is not.

That transaction split deliberately rejects any cross-count consistency invariant.
A process crash after the authoritative commit but before the shared transaction may
leave an identifier failure without tuple/IP evidence. The records also measure
different units — failures for the identifier, distinct submitted identifiers for the
IP bucket — so no arithmetic relationship between them is meaningful even without a
crash. Tests, migrations, and future integrity checks must not require their counts to
reconcile. The identifier record is authoritative; shared records are independent,
best-effort abuse signals.

Identifier-first ordering also keeps the authoritative transaction off the contended
path: it never remains open while a shared parent lock waits for up to one second. A
process death between commits under-counts the advisory distinct-identifier signal,
which can only reduce shared collateral backoff; it cannot erase the authoritative
failure or create a lock. That is the intentional failure direction for a best-effort
control.

Windows are fixed, with their start stored and rollover performed atomically in SQL.
The design accepts and documents a boundary burst of at most `2N`; thresholds must
be chosen with that property rather than described as a sliding guarantee. Window
and lock deadlines use `DatabaseTime`, and all increment/rollover/threshold behavior
requires real three-engine contention tests.

Locks are duration-bounded. Time expiry is 2.3b's documented sufficient unlock path;
there is no administrative unlock before 2.4 can make that security-relevant action
auditable. The configured duration defaults to 900 seconds and may not exceed 3600
seconds: that is the maximum time a legitimate user may be stranded while no audited
operator escape exists. A larger value fails at boot and names the 2.4 audited-unlock
dependency; it is never silently clamped. Expiry must be enforced on the request
path, never by `vouch:prune`.

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
successful authentication may reset identifier-specific failure state. It never
resets tuple markers or shared IP, tenant, global, or issuance-volume state, because
one successful account must not erase aggregate abuse or make the same tuple look new
again in the current window.

## Security budgets and defaults

The explicit worst-case target is a successful online guess probability no greater
than `10^-4` per submitted identifier across a fixed-window boundary for any current
six-digit OTP or TOTP factor. The constraints and adopted defaults below are
normative. Shared-dimension numeric limits remain open where explicitly marked.

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
| Lock duration | 900 seconds; maximum 3600 | Wait-out-able; larger values fail at boot and require 2.4's audited unlock |
| Challenge attempts | 5 | Per challenge; exhaustion invalidates that challenge |
| Issuances per identifier | 5 per 900 seconds | Multiplies with challenge attempts; first identify/issuance counts once |
| Identifier + IP tuple | No independent threshold | Per-window distinctness marker for the IP spread counter; never refuses work itself |
| IPv6 `/64` | Observe at 30 distinct submitted identifiers per 900 seconds | Usually one subscriber; enforcement disabled by default |
| IPv4 address | Observe at 300 distinct submitted identifiers per 900 seconds | Must tolerate NAT/CGNAT populations; enforcement disabled by default |
| Tenant | Observe only; enforcement threshold `null` | Opt-in, very-high refusal-only load shedding; never reported as account lockout |
| Global | Observe only; enforcement threshold `null` | Opt-in circuit breaker with the widest blast radius; never reported as account lockout |
| Throttle prune retention | 86400 seconds | Must be at least `window_seconds + maximum_lock_duration_seconds` |
| Shared-dimension lock wait | 1 second, fixed ceiling | Verified contention skips only that advisory dimension; host connection setting is restored |

Configuration is global in 2.3b, following the existing environment-backed package
config; every enabled numeric limit is an integer, while tenant and global thresholds
may be `null` to remain disabled. Per-tenant tuning is deferred: tenant is a counter
dimension now, not a second configuration resolver and storage system in this phase.

Identifier, challenge-attempt, and challenge-issuance limits enforce their adopted
defaults. Shared dimensions ship in **observe mode**. IPv6 `/64` and IPv4 counters use
30 and 300 as observation thresholds but do not refuse or delay a request until an
operator explicitly enables enforcement from measured traffic. Tenant and global
counters likewise remain live for aggregate measurement while their enforcement
thresholds are `null`. This makes the first production deployment incapable of
creating shared-bucket collateral denial from an unmeasured default.

The IP values now count distinct failing submitted identifiers, not raw failures.
Thirty therefore means one IPv6 `/64` touched thirty identifier subjects in the
window; three hundred means the equivalent for one IPv4 address. A legitimate user
who repeatedly mistypes one credential contributes one, while automated breadth is
what advances the bucket. The 30/300 values were originally proposed under raw-failure
semantics and remain observation markers, not evidence-backed enforcement defaults;
observe-mode distributions are expected to justify keeping or lowering them before
either family is armed.

Enabling a shared dimension is a fail-loud configuration transition, not the
presence of a number that happens to be non-null. It requires an explicit enforcement
mode, a threshold, and an explicitly configured seconds-scale backoff bound; the
package supplies no fabricated shared-backoff duration. IP enforcement remains
backoff-only, never lock authority, and the IPv4 threshold must remain greater than
the IPv6 `/64` threshold. Tenant and global enforcement remains refusal-only and
opt-in.

Validation is relational and fail-loud. In addition to positive integer/type checks:
`backoff_after < lock_after`, `backoff_cap_seconds <= window_seconds`, and throttle
prune retention must be at least `window_seconds +
maximum_lock_duration_seconds`. Lock duration greater than 3600 seconds fails at boot
and names 2.4's audited administrative-unlock dependency. Tenant and global limits
accept `null` as disabled rather than inventing a dangerously broad default. The
shared enforcement mode must reject a missing threshold or backoff bound rather than
silently falling back to the observation values.

Blast radius and aggressiveness are inversely proportional. Identifier state affects
one account and may progress from backoff to lock. Tuple state requires both subjects
to collide and may refuse work. IPv6 `/64` and especially shared IPv4 buckets receive
only short backoff, with the IPv4 threshold higher. Tenant and global controls can
refuse work only when an operator explicitly enables their high thresholds. No shared
dimension may write lock state or present a populated `lockedUntil`.

Equalized increments intentionally let an attacker grow the table and drive shared
dimensions using submitted identifiers that do not exist. That is the accepted cost
of closing the counter-state account-existence channel. Dedicated pruning bounds the
storage consequence; disabled-by-default widest buckets, generous shared thresholds,
short backoff caps, and the prohibition on shared lock authority bound the collateral
denial consequence.

Observe mode is aggregate, not a reason to restore readable keys. 2.3b ships a
read-only `vouch:throttle:report` surface with human-readable and `--json` output. It
reports, per dimension, active bucket count, count distribution, and how many buckets
crossed a configured observation threshold. It emits no digest, identifier, IP,
tenant key, or per-bucket row. This is ephemeral operational measurement over the live
retained window, not a security-event audit trail and not a substitute for 2.4's
redacted `AuditSink`. Tests must prove the report cannot disclose or correlate a
subject while still distinguishing the aggregate distributions needed to decide
whether enforcement is safe.

The aggregate-only rule applies to inputs as well as outputs. The report and its
underlying public contract accept no identifier, IP, tenant key, digest, or generic
subject filter and expose no candidate-lookup operation. Because the application can
derive the deterministic HMAC for a supplied candidate, a `--ip`, `--identifier`, or
similar filter would be subject-level lookup even if neither the digest nor raw value
were printed. Tests and the console signature must pin that absence. Subject-specific
operability waits for 2.4's redacted, auditable path; it is not smuggled back as a
reasonable-sounding debug option.

## Inherited mutation re-ruling

`AuthChallenge::$attempts` currently has no consumer. Its integer cast was
dispositioned equivalent only under that present fact. 2.3b gives the field its first
reader/writer for challenge caps, so the disposition is no longer inherited: the
counter's type, increments, threshold boundary, and invalidation semantics require
their own tests and mutation review.
