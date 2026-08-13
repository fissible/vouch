# Phase 2.2 — Factor Contract and Drivers: Design Specification

**Date:** 2026-08-12
**Status:** Approved design, not yet implemented
**Parent spec:** [`2026-08-11-vouch-design.md`](2026-08-11-vouch-design.md)
**Depends on:** Phase 1 (`Vouch\Kernel`) and Phase 2.1 (persistence foundation), both merged

---

## 1. Scope

2.2 delivers the `Factor` contract and five drivers: **password, TOTP, email OTP, SMS
OTP, and recovery codes**. It also lands three amendments to 2.1, each versioned and
tested as part of this slice rather than deferred.

**Passkey moves to its own sub-project, 2.2b**, gated on a hard evaluation of
`laravel/passkeys`. That package is at v0.2.1 — pre-1.0, first released April 2026 and
already through a minor bump — which is an unstable API under a security-critical driver
in a compliance-positioned package. Parent spec §6.4 set this precedent for the OIDC
client, and the same reasoning applies: five working drivers must not wait on one
unevaluated dependency, and passkey is independently the most complex driver, carrying
the WebAuthn relying-party binding of §4.1.

2.2 delivers **no HTTP surface and no flow orchestration**. Nothing here logs anyone in.
Routes, `RequireAssurance`, rate limiting, and the recovery-grace enforcement rules
remain 2.3.

### Fortify is not a dependency

Parent spec §3.2 names Fortify for the password, TOTP, and recovery-code drivers. On
inspection it earns none of them:

| Need | What Fortify adds | The actual primitive |
|---|---|---|
| Password hashing | a wrapper | `illuminate/hashing` — already a dependency |
| TOTP | `TwoFactorAuthenticationProvider` | `pragmarx/google2fa` |
| Recovery codes | `RecoveryCode`, ~10 lines of `Str::random` | nothing — and vouch's requirements differ anyway |

Fortify is authentication *scaffolding*: routes, controllers, view-response contracts,
and its own login flow. Vouch owns the flow — §8.4 replaces Filament's auth pages rather
than plugging into them — so Fortify's would be dead weight at best and a second system
owning login at worst, which is precisely the fragmentation vouch exists to remove.
Fortify also drags in `laravel/passkeys ^0.2.0` transitively, coupling the passkey
decision to the password decision.

Dropping it does **not** violate §1's rule against reimplementing cryptography a
maintained first-party package provides. Laravel's `Hash` and a real TOTP library *are*
those packages; Fortify is a layer above them.

### Dependencies added

- **`spomky-labs/otphp ^11.5`** for TOTP.
- **`spatie/laravel-one-time-passwords ^1.1`** for OTP generation and delivery.

Both TOTP candidates were checked for constant-time comparison, because a security
package should not choose a crypto library on reputation: `pragmarx/google2fa` uses
`hash_equals` at `Google2FA.php:80`, and `spomky-labs/otphp` at `OTP.php:342`. Neither
has a gap. otphp was chosen on maintenance posture — more recently released, a PHP 8.1+
floor matching this package rather than carrying 7.1 compatibility, strict RFC
4226/6238, and all three of its verification paths (exact and both leeway windows)
funnelling through a single `compareOTP()` choke point that is easier to audit than
comparisons spread across call sites.

---

## 2. The `Factor` contract

Parent spec §3.1 sketched this before the persistence layer existed, so three of its
types were placeholders. Reconciled:

```php
interface Factor
{
    /** Registry key. Matches auth_credentials.type. */
    public function id(): string;

    public function kind(): FactorKind;
    public function strength(): FactorStrength;

    /** 1, a finite number, or null for unbounded. Counted over ACTIVE credentials only. */
    public function maxActiveCredentials(): ?int;

    public function enroll(int $userId, array $data): EnrollmentResult;

    /** Null when the factor needs no challenge (password, TOTP, recovery code). */
    public function challenge(ChallengeRequest $request): ?AuthChallenge;

    public function verify(AuthAttempt $attempt, array $input): FactorResult;

    public function revoke(AuthCredential $credential): void;
}
```

`int $userId` rather than a user model: vouch never references the host's
authenticatable class, and every foreign key in the schema is a plain integer.

### `ChallengeRequest` — a credential cannot be required

`challenge()` takes a request object, not an `AuthCredential`, because several valid
flows do not know a credential at challenge time:

- email and SMS OTP are addressed via the attempt's identifier;
- recovery-code verification selects the matching code only *after* input arrives;
- passkey assertion (2.2b) begins before the authenticator has selected a credential.

Forcing drivers to invent a credential merely to satisfy a signature would be a lie in
the type system.

```php
final readonly class ChallengeRequest
{
    public function __construct(
        public AuthAttempt $attempt,
        public ?AuthCredential $credential = null,
        public ?string $clientIp = null,
        public ?string $clientUserAgent = null,
    ) {}
}
```

Client IP and user-agent travel here because `auth_challenges` binds them (§7.4) and the
attempt carries only `bound_context`, which is the session.

### `maxActiveCredentials()`, not a boolean

A boolean cannot express a recovery-code *set*, and "one TOTP secret" is a current
product rule rather than an intrinsic property of TOTP.

| Driver | Max active | Reason |
|---|---|---|
| `password` | 1 | product rule |
| `totp` | 1 | product rule, trivially raisable |
| `email_otp`, `sms_otp` | `null` | bounded naturally by verified identifiers |
| `recovery_code` | 10 | a set |
| `passkey` (2.2b) | `null` | genuinely unbounded |

**Counted over active credentials only** — `disabled_at IS NULL`. A revoked TOTP must
never block enrolling its replacement; that would be a self-inflicted lockout.

### `EnrollmentResult`

Refined while specifying: `enroll()` cannot return a bare `AuthCredential`, because
recovery-code enrollment creates ten of them and both TOTP and recovery produce
plaintext that is shown once and never retrievable again.

```php
final readonly class EnrollmentResult
{
    /**
     * @param list<AuthCredential> $credentials
     * @param list<string> $oneTimeSecrets Displayed once at enrollment; never re-retrievable.
     */
    public function __construct(
        public array $credentials,
        public array $oneTimeSecrets = [],
    ) {}
}
```

TOTP returns one credential plus its provisioning URI; recovery returns ten credentials
plus ten plaintext codes; password and OTP return one credential and nothing else.

### `FactorResult`

```php
final readonly class FactorResult
{
    public static function satisfied(SatisfiedFactor $factor, SingleUseMutation ...$mutations): self;
    public static function failed(FactorFailure $reason): self;
}
```

On success the driver constructs the kernel's `SatisfiedFactor`. This is the seam
between Phase 2 and Phase 1: the driver is the only component that knows whether user
verification actually occurred, whether its mechanism is phishing-resistant, and which
credential was used. It reports those honestly and hands them over; the kernel decides
satisfiability. **Drivers never evaluate policy.**

`FactorFailure` is an internal enum — `NoCredential`, `Mismatch`, `Expired`, `Consumed`,
`Malformed` — reported **truthfully and never pre-redacted**. The kernel's `ErrorShaper`
is the only response-facing boundary and decides disclosure under the tenant's
enumeration posture. A driver that self-censored would make §7.1.1's strict-mode
guarantee unverifiable, because there would be two places deciding what a response may
reveal.

---

## 3. Single-use state belongs to the store

**Drivers validate. The store owns every single-use mutation.**

2.1 already consumes challenges atomically with the attempt transition. Recovery codes
and the TOTP replay guard need the same treatment, and a driver-side guarded update is
wrong for both:

- if the subsequent transition fails, a recovery code is burned while the user remains
  unauthenticated — the same denial-of-service shape as the lost-CAS challenge burn that
  2.1's rollback test exists to prevent, arriving through the credential table;
- two submissions could each validate before either writes.

So `FactorResult` carries typed mutations that the store executes **inside its
transaction**.

### The mutation types

```php
interface SingleUseMutation
{
    /** Stable conflict key, e.g. "credential:17" or "challenge:42". */
    public function target(): string;
}

final readonly class ConsumeChallenge implements SingleUseMutation { /* challengeId */ }
final readonly class DisableCredential implements SingleUseMutation { /* credentialId */ }
final readonly class AdvanceCredentialTimestep implements SingleUseMutation { /* credentialId, timestep */ }
```

Typed value objects rather than driver-supplied SQL: the store knows how to execute each
one, so there is no injection surface and every single-use mutation is auditable in a
single place.

### What the store must reject

The transaction boundary stays authoritative as future drivers are added, so the store
refuses three things:

1. **Duplicate or conflicting mutations for one target.** Two mutations sharing a
   `target()` in one call is a programming error and throws. Silently applying both, or
   arbitrarily picking one, would make the outcome depend on ordering.
2. **Unknown mutation types.** PHP has no sealed interfaces, so a future driver could
   pass an implementation the store cannot execute. The store matches on known types and
   throws on anything else — it must never skip a mutation it does not understand, which
   would silently drop a single-use guard.
3. **Any mutation affecting other than exactly one row.** Zero means the guard already
   fired — consumed, replayed, or concurrently taken — and rolls the transaction back.
   More than one means the predicate was wrong and is a bug; both refuse.

Programming errors (1 and 2) throw. Runtime refusals (3) return a `TransitionOutcome`,
so callers distinguish "you built this wrong" from "you lost the race."

### Guarded predicates

| Mutation | Guarded update |
|---|---|
| `ConsumeChallenge` | `SET consumed_at = CURRENT_TIMESTAMP WHERE id = ? AND attempt_id = ? AND consumed_at IS NULL AND expires_at > CURRENT_TIMESTAMP` |
| `DisableCredential` | `SET disabled_at = CURRENT_TIMESTAMP WHERE id = ? AND disabled_at IS NULL` |
| `AdvanceCredentialTimestep` | `SET last_used_timestep = :step WHERE id = ? AND (last_used_timestep IS NULL OR last_used_timestep < :step)` |

Each requires exactly one affected row. New `TransitionOutcome` cases:
`CredentialAlreadyConsumed` and `TimestepReplay`.

---

## 4. Amendments to Phase 2.1

Three, all to merged and reviewed code. Each ships with tests in this slice.

### Amendment A — `auth_credentials.identifier_id`

OTP credentials must reference the address they deliver to. The kernel's
`require_distinct_credentials` keys on `credentialId`, so a factor with no credential
cannot participate in distinctness — OTP therefore needs credential rows, and their
identity *is* the destination address. `auth_credentials` has no link to
`auth_identifiers`; `authenticator_id` and `relying_party_id` mean other things, and
overloading `authenticator_id` would corrupt `require_independent_authenticators`, which
consumes it.

```php
$table->foreignId('identifier_id')->nullable()
      ->constrained('auth_identifiers')
      ->restrictOnDelete();

$table->unique(['user_id', 'type', 'identifier_id']);
```

**The `NULL` semantics here are deliberate, and the inverse of the 2.1 session-binding
case.** There, `NULL != NULL` broke the constraint by permitting multiple live rows.
Here it is exactly right: OTP credentials always carry a non-null `identifier_id` and are
constrained; password, TOTP, recovery and passkey rows carry `NULL` and are left to their
`maxActiveCredentials()` rules. This must be stated in the migration, because it looks
like the mistake that was just fixed.

**Three application-level guards**, since no foreign key can express them:

1. **Same-user.** The referenced identifier must belong to the credential's user. Two
   independent FKs cannot relate them.
2. **Verified.** An unverified identifier is attacker-supplied until proven; linking OTP
   delivery to one would let an attacker route codes to their own address.
3. **Value immutability once referenced.** `AuthIdentifier.value` freezes as soon as any
   credential references it. Changing an address means creating and verifying a *new*
   identifier, then enrolling a new OTP credential. Mutating in place would silently
   redirect every existing OTP credential pointing at that row — an account takeover
   requiring no credential change at all.

**Referenced identifiers are retained indefinitely.** `restrictOnDelete()` blocks
deletion regardless of `disabled_at`, so "disabled, therefore deletable" is false. There
is no retirement workflow in v1: an address that ever served as an authentication
destination is permanent audit history, which suits a security package and pairs with
immutability so the record can be neither edited nor erased.

**Re-enrollment re-enables rather than inserts.** The unique index counts disabled rows,
so a disabled OTP credential for an address would otherwise block re-enrollment. A
partial index is not portable across the three engines. The semantic fix is honest for
OTP specifically, because these credentials are secretless — the code lives in
`auth_challenges`, so re-enrollment genuinely *is* re-enabling. It is one atomic
operation that must:

- resolve the existing `(user_id, type, identifier_id)` row;
- re-check same-user and `verified_at`;
- clear `disabled_at` rather than insert;
- **preserve the credential ID**, so `auth_token_assurances.credential_ids` references
  and kernel distinctness stay coherent;
- emit an audit event for the re-enable.

This asymmetry holds only because OTP credentials are secretless. Password and TOTP
re-enrollment must still create a fresh row with a new secret.

### Amendment B — `auth_credentials.last_used_timestep`

Nullable unsigned big integer. RFC 6238 §5.2 requires that an accepted OTP not be
accepted a second time, and a wall-clock `last_used_at` cannot reliably recover *which*
timestep was accepted once a leeway window is allowed: a code from timestep `T+1` can be
accepted while wall-clock sits in period `T`, so deriving the timestep from
`last_used_at` yields `T`, and replaying the `T+1` code passes a `>` check again. The
guard would look correct and permit the exact replay the RFC forbids.

`last_used_at` remains operational metadata. It is not the security guard.

### Amendment C — `AttemptStore::transition()` signature

```php
// 2.1
public function transition(AuthAttempt $a, AttemptState $to, ?int $consumeChallengeId = null): TransitionOutcome;

// 2.2
public function transition(AuthAttempt $a, AttemptState $to, SingleUseMutation ...$mutations): TransitionOutcome;
```

Technically breaking, though the only callers today are tests. Taken deliberately rather
than bolting on a second nullable integer parameter, which would leave a signature
nobody can extend when 2.2b adds passkeys.

---

## 5. The five drivers

| Driver | kind / strength | Max active | Challenge | Secret at rest | Mutations on success |
|---|---|---|---|---|---|
| `password` | knowledge / knowledge | 1 | none | `Hash` digest | none |
| `totp` | possession / possession | 1 | none | otphp secret, `encrypted` cast | `AdvanceCredentialTimestep` |
| `email_otp` | possession / possession_weak | null | code → `auth_challenges` | none | `ConsumeChallenge` |
| `sms_otp` | possession / possession_weak | null | code → `auth_challenges` | none | `ConsumeChallenge` |
| `recovery_code` | possession / **recovery** | 10 | none | `Hash` digest, one row per code | `DisableCredential` |

Every driver sets `isMultiFactor`, `userVerified` and `phishingResistant` to `false` on
the `SatisfiedFactor` it produces. All five are single-factor and none is
phishing-resistant; those attributes exist for passkeys, and defaulting them false is the
fail-closed direction.

**`recovery_code` carries `FactorStrength::Recovery`**, which the kernel filters out of
both satisfiability and assurance facts. A recovery code therefore cannot satisfy any
policy *by construction*, not by driver discipline — the guard lives in code that is
mutation-tested.

**Recovery-code regeneration** disables every active recovery credential before creating
the new set, satisfying §7.3's "regeneration invalidates all prior codes."

**Password rehash-on-verify** is deliberately out of scope for v1 and recorded as a
follow-up. It is a credential write on the verification path, and mixing it into the
single-use mutation machinery for a non-security-critical optimisation would muddy a
boundary worth keeping sharp.

---

## 6. Testing

Real databases throughout, following 2.1. The adversarial matrix runs against SQLite,
MySQL and Postgres, because SQLite is a supported target but cannot prove the other
engines' locking and transaction behaviour.

Beyond per-driver enrollment and verification, the suite must pin:

- **TOTP replay.** The same code accepted once must be refused on a second submission,
  including across a leeway window — the case a `last_used_at`-derived guard would have
  let through.
- **Recovery-code single use under contention.** Two connections submitting the same code
  must yield exactly one success, with the loser's credential left enabled.
- **Consumption rolls back with a failed transition.** A recovery code must not be burned
  when the attempt transition subsequently fails.
- **Store rejection rules.** Duplicate targets throw; unknown mutation types throw; a
  mutation affecting zero rows refuses and rolls back.
- **Identifier guards.** Cross-user linkage refused; unverified identifier refused;
  mutating a referenced identifier's value refused.
- **Re-enrollment preserves the credential ID** rather than inserting a duplicate.
- **Recovery codes cannot satisfy a policy**, asserted through the kernel evaluator
  rather than by inspecting driver metadata.

Each new guard must be demonstrated failing against a deliberate violation before being
trusted, per the discipline established in Phase 1 and 2.1.

---

## 7. Out of scope for 2.2

- **Passkey** — sub-project 2.2b, gated on evaluating `laravel/passkeys` 0.2.x.
- **HTTP surface, routes, middleware, rate limiting** — 2.3.
- **Recovery-grace enforcement.** 2.2 provides the recovery-code driver; the grace
  session's permitted/denied list, absolute TTL, and route enforcement are 2.3.
- **Typed enrollment and verification DTOs.** `enroll()` and `verify()` take arrays in
  v1, validated per driver at entry. `ChallengeRequest` is typed because it carries
  several well-known values; enrollment and verification inputs are genuinely
  heterogeneous. Recorded as a follow-up.
- **Password rehash-on-verify.**
- **OIDC** — 2.5.

---

## 8. Decision log

| Decision | Choice | Rationale |
|---|---|---|
| Fortify | Not a dependency | It wraps primitives vouch can use directly, brings a competing login flow into a package that owns the flow, and pulls `laravel/passkeys` 0.x transitively. Dropping it does not violate §1, because `Hash` and a TOTP library are the maintained primitives. |
| Passkey | Split to 2.2b, evaluation-gated | `laravel/passkeys` is pre-1.0 and the driver is the most complex. Same precedent as §6.4's OIDC gate. |
| TOTP library | `spomky-labs/otphp` | Both candidates verified to use `hash_equals`, so no security gap decided it. Chosen on maintenance recency, a PHP 8.1+ floor, and a single `compareOTP()` choke point. |
| `challenge()` input | `ChallengeRequest`, credential optional | OTP, recovery and passkey flows all lack a known credential at challenge time. |
| Credential cardinality | `maxActiveCredentials(): ?int` over active rows | A boolean cannot express a recovery-code set; disabled rows must not cause lockout. |
| Single-use state | Owned entirely by the store, via typed mutations | A driver-side guarded update burns a code when the transition later fails, and permits two validations before either writes. |
| Store strictness | Rejects duplicate targets, unknown types, and any non-single-row effect | Keeps the transaction boundary authoritative as drivers are added. |
| TOTP replay guard | Dedicated `last_used_timestep` | A wall-clock timestamp cannot recover the accepted timestep under a leeway window, and the resulting guard would permit the replay it appears to prevent. |
| Identifier retention | Retained indefinitely; no v1 retirement workflow | `restrictOnDelete()` blocks deletion regardless of `disabled_at`, so "disabled, therefore deletable" is false. Permanent audit history suits a security package. |
| OTP re-enrollment | Re-enables the existing row, preserving its ID | The unique index counts disabled rows and partial indexes are not portable. Honest only because OTP credentials are secretless. |
| Failure reporting | Truthful in the driver; disclosure only in `ErrorShaper` | Two components deciding disclosure would make the strict-posture guarantee unverifiable. |
