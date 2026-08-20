# Vouch Phase 2.3d — Account lifecycle (Fortify parity)

## Goal

Close the gap between "the login ceremony" and "an auth layer someone can install",
without weakening any boundary that already exists.

Measured against Fortify — the package people will unconsciously compare this to —
Vouch already does login, two-factor and password confirmation *better*. It is
missing identifier verification, credential recovery, first-credential enrolment
and credential self-service.

**Revised after review.** An earlier draft claimed all four were compositions of
existing subsystems. That is true of Tasks 2–4 and **false of Task 1**: the OTP
path deliberately refuses unverified identifiers, and every challenge is
structurally bound to a login attempt. Task 1 is new machinery.

## Sequencing note

**Task 1 is not a feature gap; it is an install cliff.** `AuthFlow` resolves
identifiers with `whereNotNull('verified_at')` and nothing shipped sets that
column, so a fresh install cannot log anyone in and the refusal is deliberately
undiagnosable.

Task 1 is more urgent than 2.3c but is not a dependency of it: 2.3c protects SMS
spend, which only matters once SMS OTP is reachable, which requires Task 1.
**Recommended order: 2.3d Task 1 → 2.3c → the rest of 2.3d.** A decision to take,
not one already taken.

## Effort and critical path

| Task | Estimate | Depends on | Notes |
|---|---|---|---|
| 1. Identifier verification subsystem | **L** | — | New machinery; unblocks adoption |
| 2. Credential recovery (password reset) | M | 1 | Reuses grace |
| 3. First-credential enrolment service | S | 1 | Parallel with 2 |
| 4. Credential self-service | M | 2 | Needs the grace matrix |
| 5a. Authorization integration survey | S | — | Verification, not design |
| 5b. Ability → assurance requirement map | M | 5a | Design follows the survey |
| 6. Suggest `spatie/laravel-permission` + recipe | XS | 5b | Docs |
| 7. Positioning: tagline and non-goals | XS | — | Parallel |

Critical path: 1 → 2 → 4.

## Non-negotiable constraints

1. **No ceremony creates a session except login.** Verification, reset and
   enrolment prove control of something; none authenticates a browser.
2. **Every *public* ceremony endpoint is enumeration-safe.** Requesting
   verification and requesting a reset must respond identically whether or not the
   identifier exists, is registered-unverified, or is already verified. Enrolment
   is **not** in this list — it is a service call with no public route (Task 3).
3. **Every code-bearing ceremony reuses the encrypted outbox** for transport. No
   new synchronous provider call and no second plaintext store.
4. **Ceremonies are throttled on their own dimension**, not by borrowing the login
   issuance intent (Task 3 rationale below).
5. **Credential change revokes other sessions, with a stated failure order.** See
   the ordering contract below — this cannot be a single transaction.
6. **Vouch never creates the host's `User` row.**

## The credential-change ordering contract

Revocation and credential mutation **cannot share a transaction**. The desired
failure behaviour is that revocation survives a failed mutation, and a rollback
would undo both. So they are separate transactions with a fixed order and a stated
residual.

The two failure modes are not symmetric:

| Order | If the second step fails | Verdict |
|---|---|---|
| mutate, then revoke | sessions predating the change stay live under the new credential | **unsafe** |
| revoke, then mutate | every other session ends; credential unchanged | safe, merely annoying |

**Chosen: commit revocation first, then mutate in a second transaction.**

- **Recovery path when mutation fails.** The operation reports failure, not partial
  success. The old credential still works, so the user simply signs in again — no
  administrative action, which matters because audited administrative recovery does
  not exist until 2.4.
- **The race, stated rather than ignored.** Between the two commits a login using
  the *old* credential can create a session the first revocation never saw. The
  window is milliseconds but it is real, and it is the exact session the operation
  exists to eliminate. **Mitigation: revoke again after the mutation commits.**
  Revocation is idempotent — "revoke every session for this user other than the
  current one" — so the second pass is cheap and closes the window.
- **Residual.** If the second revocation fails, a session created inside the window
  survives. Narrower than the unsafe ordering, and it must be recorded rather than
  presented as impossible.
- **Scope.** "Other sessions" excludes the session performing the change.
- **Store boundary.** `auth_sessions.revoked_at` is a database write and is what
  `ValidatesVouchSession` enforces. The host's session-store rotation stays outside
  both transactions and is best-effort, matching `SessionLifecycle`'s existing
  split.

## Task 1: Identifier verification subsystem — **L**

Prove control of an identifier and set `verified_at`.

**Why this is not a composition.** `OtpChallengeOutbox::issue()` throws for an
identifier with `verified_at === null`, and that guard is correct — sending a login
code to an unverified address would let whoever registered someone else's email
receive their login codes. It stays. Separately, `auth_challenges.attempt_id` is a
non-null foreign key, so every challenge belongs to a login attempt; a verification
has none.

**Purpose separation is type-level, not a flag.** A verification code must be
structurally incapable of satisfying a login challenge. Follow the precedent set by
`BindingDomain`, whose docblock explains why the argument is required rather than
defaulted: cross-context derivation must be unwritable, not merely discouraged.

Requirements:

- **Its own store**, attempt-independent, with its own TTL, single-use rule and
  consumed-state. Not a nullable `attempt_id` on `auth_challenges`.
- **Its own send path** reusing the outbox transport, with a target rule that
  permits unverified identifiers *for this purpose only*.
- **Enumeration.** Identical shape and timing for unregistered,
  registered-unverified and already-verified addresses. Reuse the decoy pattern the
  issuer already models.
- **Not an authentication.** Success sets `verified_at` and nothing else: no
  `auth_session`, no guard call, no policy satisfaction.
- **Re-verification** behaves identically to first verification, since divergence
  is an oracle.
- **Throttled** on the ceremony dimension (Task 3 rationale).
- **Host guidance**: document that an unverified identifier is invisible to login
  by design, because it is the first failure a new adopter will hit.

Proofs: sets the column; creates no session; unknown/unverified/verified are
indistinguishable; a verification code is rejected as a login factor **and** cannot
be redeemed against any `auth_challenges` row; sends are counted for decoys.

## Task 2: Credential recovery (password reset) — M

Prove control of a verified identifier, open a time-boxed capability, re-enrol the
credential. Composition: verification-style proof → `GraceGuard` →
`PasswordFactor::enroll()`.

**Assurance policy — decided.** Reset flows in the wild let inbox control bypass a
second factor, quietly making every account single-factor.

- **Default (b): record post-reset assurance honestly as single-factor.** Inbox
  control is one possession factor and is recorded as such, so per-route step-up
  still guards everything sensitive. This is safe *because* assurance is enforced
  per route — the differentiator used properly — and it does not lock out a user
  who lost both factors.
- **Configurable (a): require the second factor during reset** when the account has
  one. Stronger for the account, recreates the lockout that recovery codes exist to
  solve. Must be tested in both modes, not merely offered.
- The third option — full assurance from inbox control alone — does not ship.

Further requirements: session revocation per the ordering contract above; reuse
grace rather than inventing a reset-token table; enumeration-safe request; single
use with no restoration by a later delivery failure; **no implicit login**.

## Task 3: First-credential enrolment service — S

Attach a first identifier and credential to a user the host has already created,
and trigger Task 1's ceremony.

- **Service-only. No public route.** A public credential-writing endpoint is an
  enumeration surface and a credential-injection surface at once.
- **Neutral host-facing result contract.** The service returns a result that does
  not reveal whether the identifier already existed. Enumeration safety at the
  *host's* registration endpoint is then achievable rather than accidentally
  foreclosed — document the safe pattern rather than leaving the host to invent it.
- **Concurrency semantics, stated explicitly**: retry of the same enrolment;
  re-enabling a disabled credential; duplicate unique-key races. `EnrollmentGuard`
  already serializes per `(user_id, type)` and should be the mechanism.
- **The first identifier starts unverified.**

**Ceremony throttling — the dimension decision.** `ChallengeIssuanceIntent`
requires a non-nullable `attemptId`, plus factor and action metadata. Verification,
reset and enrolment have no login attempt. Rather than weaken a type that is
currently non-nullable, ceremonies get **their own throttle dimension** keyed on
identifier and IP digests. They reuse the 2.3b *store* and its atomicity, not the
login *intent* — and ceremony volume is a different budget from login volume in any
case.

## Task 4: Credential self-service — M

Change password, add or remove an authenticator, regenerate recovery codes, add a
second identifier. Every operation requires step-up.

**The grace-capability matrix — required, because step-up alone contradicts
itself.** `AssuranceComparator` returns `false` for any recovery-grace session, so
grace satisfies *no* assurance level. "Every operation requires step-up" therefore
makes recovery self-service impossible by construction: a user in grace could never
regenerate codes or replace the factor they lost, which is precisely what grace is
for.

Grace capability is a separate axis from the assurance ladder:

| Operation | Grace may | Why |
|---|---|---|
| Regenerate recovery codes | **yes** | A user who spent their last code must be able to get more |
| Enrol a replacement second factor | **yes** | The purpose of grace |
| Change password | **no** | Code control alone must not rewrite the primary credential; that is the reset ceremony, with its own evidence rules |
| Remove an existing factor | **no** | Destructive, and reduces future recovery options |
| Add or verify a new identifier | **no** | Adding a delivery target during recovery is an account-takeover primitive |
| Mint API tokens | **no** | Already required by the 2.1 design |

Further: removing a factor a policy requires must be refused, not silently allowed;
removing or replacing a factor revokes other sessions under the ordering contract
and re-evaluates the current session's assurance; a new identifier starts
unverified.

## Task 5a: Authorization integration survey — S

**Verification before design.** An earlier draft asserted that a central
`Gate::before` hook would cover `spatie/laravel-permission`, Bouncer and plain
Gates. That was an assumption, not a measured fact: an authorization package whose
middleware calls model methods directly never reaches `Gate` at all.

Deliverables:

- Determine empirically, per integration, which authorization APIs route through
  `Gate` — `$user->can()`, `@can`, policies, and each package's own middleware.
  Install the packages as **`require-dev`** for this; test-only dependency, not a
  runtime `require`.
- Determine what is enumerable for a strict mode. `Gate::abilities()` covers
  explicitly defined abilities but not policy methods or database-backed
  permissions, so "unknown ability at boot" is implementable only against a
  host-declared list or a per-integration registry.
- Output: a coverage table stating honestly what is and is not enforceable per
  integration.

## Task 5b: Ability → assurance requirement map — M

```php
'assurance_requirements' => [
    'invoices.approve'  => 'aal2',
    'users.impersonate' => 'aal3',
],
```

Design follows 5a's findings. Fixed regardless:

- **Authorization-agnostic keys.** Ability *names*, no dependency on any package.
- **Deny only; never grant.** The hook defers with `null` when it has no opinion. A
  hook that can return `true` is an authorization bypass — far worse than the gap
  it closes.
- **Insufficient assurance is not forbidden.** Interactive requests step up via
  `Vouch::stepUp()`. The non-interactive shape aligns with the RFC 9470 work
  already scheduled for 2.4 rather than inventing a second vocabulary — so the map
  is **session-sourced until 2.4**, stated rather than failing open on token
  requests.
- **Typos must not silently disable protection**, within whatever bound 5a shows to
  be achievable. Ship an inspection command listing effective requirements.
- **Redirecting from an authorization callback is a design question**, not an
  assumption: 5a must establish whether it is acceptable in each integration.

## Task 6: Suggest `spatie/laravel-permission` — XS

```json
"suggest": {
    "spatie/laravel-permission": "Role and permission authorization; Vouch handles authentication only"
}
```

Plus the composition recipe:

```php
->middleware(['vouch.assurance:aal2', 'permission:invoices.approve'])
```

No runtime dependency, no bundled migrations, no inherited release cycle.

## Task 7: Positioning — XS

> **Vouch** — proves who someone is, and how well. What they may do stays yours.

Followed immediately by the two-middleware example. Non-goals — authorization,
token storage, UI — above the fold.

## Commit sequence

One task per commit, tests with the code, no task with a public surface landing
without its enumeration proof. Task 1 ships before any adoption guidance changes.
