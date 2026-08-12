# fissible/vouch — Design Specification

**Date:** 2026-08-11
**Status:** Approved design, not yet implemented
**Author:** Design session (Allen McCabe + Claude)

---

## 1. Summary

`fissible/vouch` is a Laravel authentication package that unifies password,
one-time-passcode, multi-factor, and single-sign-on authentication behind a single
policy engine, with a tamper-evident audit trail.

It is an **orchestration layer**, not a reimplementation. It composes existing,
battle-tested primitives (Fortify, `laravel/passkeys`, Socialite,
`spatie/laravel-one-time-passwords`) behind its own contracts. It never implements
cryptography or protocol handling that a maintained first-party package already
provides.

**Primary goal: security.** Secondary goal: flexibility.

### 1.1 Positioning

Target: Laravel applications under compliance pressure (SOC 2, HIPAA, or equivalent),
plus the fissible portfolio as the first consumers.

The Laravel ecosystem has solved the *primitives* — Fortify covers password,
registration, reset, verification, TOTP, and recovery codes; `laravel/passkeys` (first
party, April 2026) covers WebAuthn; Socialite covers OAuth; Spatie covers OTP;
`laravel/workos` covers enterprise SSO. What is **not** solved is a coherent policy
layer that composes them under one consistent security posture: enumeration control,
step-up authentication, account-linking rules, factor-strength policy, assurance
levels, and audit.

vouch's differentiator is **auth policy as configuration, with a tamper-evident audit
trail** — combining the policy engine with `fissible/attest-laravel`. That is
something WorkOS charges for and Fortify does not attempt.

### 1.2 First consumers

| App | Laravel | UI | Tenancy | Notes |
|---|---|---|---|---|
| `fissible/sluice` | 13.8 | Filament v5 | none | Already on Laravel 13 — first dogfood target. Has `is_service` users. |
| `fissible/station` | 12 → 13 (upgrade in progress) | Filament v5.4 | multi-tenant | Adoption gated on the Laravel 13 upgrade. |

---

## 2. Non-goals

Stated explicitly so they do not get half-built:

- **vouch does not issue or manage API tokens.** Sanctum keeps that responsibility.
- **vouch does not attempt MFA for machine actors.** Service-identity security is token
  scoping, rotation, TTL, and IP allow-listing.
- **vouch does not own authorization.** Roles, permissions, and tenant membership stay
  with the host application (`spatie/laravel-permission` in Station's case).
- **vouch does not implement SAML in v1.** See §6.4.
- **vouch does not implement WebAuthn, OIDC, or password hashing itself.** It delegates.

---

## 3. Core model: factors × policy

The original four-mode framing (password / OTP / 2FA / SSO) conflates two different
things. Password, OTP, passkey, and SSO are **first-factor methods**; 2FA is a
**policy** ("require ≥2 factors"), not a method. Email OTP is simultaneously a valid
first factor and a valid second factor, so it cannot live in exactly one mode.

The architecture is therefore **factors × policy**. The four modes survive as *presets*.

### 3.1 The `Factor` contract

```php
interface Factor {
    public function kind(): FactorKind;          // knowledge | possession | inherence
    public function strength(): FactorStrength;  // ordered enum
    public function enroll(User $u, array $data): Credential;
    public function challenge(AuthAttempt $a): Challenge;   // may be a no-op
    public function verify(AuthAttempt $a, array $input): FactorResult;
    public function revoke(Credential $c): void;
}
```

### 3.2 v1 factor drivers

| Driver | Delegates to | Strength |
|---|---|---|
| `PasswordFactor` | Laravel Hash / Fortify | `knowledge` |
| `EmailOtpFactor` | `spatie/laravel-one-time-passwords` | `possession_weak` |
| `SmsOtpFactor` | Spatie OTP + host SMS channel | `possession_weak` |
| `TotpFactor` | Fortify 2FA | `possession` |
| `PasskeyFactor` | `laravel/passkeys` | `possession_strong` |
| `OidcFactor` | Socialite + generic OIDC discovery | inherited from IdP |
| `RecoveryCodeFactor` | Fortify recovery codes | `recovery` |

`FactorStrength` is an **ordered** enum. Policy expresses `minimum: possession` and
automatically excludes weaker drivers without enumerating them, so new drivers slot in
without touching policy code.

`recovery` strength never satisfies a policy on its own (§7.3).

Factor-strength ordering reflects real-world security, not convenience:
`passkey > totp > sms > email`. NIST treats SMS as a restricted authenticator; email
OTP is the weakest possession factor because it inherits the security of an external
mailbox. vouch supports all of them and lets config flag the weak ones, but the
defaults prefer TOTP and passkeys.

### 3.3 `PolicyResolver`

Given `(identifier|user, tenant, intent, request context)`, returns an
`AuthRequirement`: the set of factor combinations that satisfy this intent.

Intents: `login`, `step_up`, `enroll_factor`, `recover`.

Resolution chain, most specific wins:

```
global config → tenant → role → user
```

### 3.4 `AuthAttempt` state machine

A server-side state machine carrying an in-progress authentication across HTTP
requests. The client holds only an opaque handle; attempt state is **never** trusted
from session or client data.

```
initiated → identified → factor_pending ⇄ factor_satisfied (×N)
                              ↓
   authenticated | registration_required | failed | locked
```

The client never learns *why* a step was demanded beyond what the enumeration posture
(§7.1) permits.

### 3.5 Presets — where the original "modes" live

```php
'presets' => [
    'password'     => ['step1' => ['password'], 'step2' => false],
    'otp'          => ['step1' => ['email_otp'], 'step2' => false],
    'mfa'          => ['step1' => ['password','passkey'],
                       'step2' => ['totp','passkey'],
                       'minimum_strength' => 'possession'],
    'sso'          => ['step1' => ['oidc'], 'step2' => 'defer_to_idp'],
    'passwordless' => ['step1' => ['passkey','email_otp'], 'step2' => false],
],
```

An app sets `'mode' => 'mfa'` and is done. An app with real requirements writes a
policy document instead. **A preset *is* a policy document** — same engine, no second
code path.

---

## 4. Data model

Nothing is added to `users`. Adoption touches zero existing columns.

| Table | Scope | Purpose |
|---|---|---|
| `auth_identifiers` | user | email / phone / username → user. `verified_at`, `is_primary`. Enables multiple emails per user, which SSO linking requires. |
| `auth_credentials` | **user, global** | Polymorphic: password hash, TOTP secret, WebAuthn credential, OIDC subject. `last_used_at`, `disabled_at`, strength snapshot. |
| `auth_challenges` | attempt | Hashed OTPs. `expires_at`, attempt counter, IP/UA binding, `consumed_at`. |
| `auth_attempts` | request | The state machine. Short TTL, cache-backed with DB fallback for audit. |
| `auth_policies` | **tenant** | Policy-as-data. Deliberately shaped like Sluice's gate engine so the two read alike. |
| `auth_connections` | **tenant** | Tenant ↔ IdP: email domain, OIDC discovery URL, client credentials, claim mappings, JIT provisioning rules. |
| `auth_link_requests` | user | Pending SSO ↔ existing-account links awaiting proof of control. |

### 4.1 Scope split rationale

- **Credentials are global to the user.** A passkey belongs to the person, not the
  tenant. Enrolling once satisfies every tenant whose policy it meets. Tenants cannot
  enumerate or manage each other's credentials.
- **Connections are tenant-scoped.** An OIDC subject from Acme's Okta must satisfy
  *only* Acme's tenant. Federated identity is not portable across tenants. **Getting
  this wrong is a cross-tenant account takeover.**

### 4.2 Migration compatibility

Existing `users.password` hashes are read through a compatibility shim and migrated
lazily on next successful login. Station's `users.app_authentication_secret` migrates
to an `auth_credentials` row of type `totp`. `php artisan vouch:backfill` performs a
one-shot migration. **No existing column is dropped in v1.**

---

## 5. Tenancy

### 5.1 Tenancy is an interface, never a model

vouch defines `TenantResolver` and `HasAuthPolicy`. It never references a Tenant class.
Ships with `NullTenantResolver` for single-tenant apps (Sluice).

Station binds a small adapter over its existing `TenantContext`:

```php
$this->app->bind(TenantResolver::class, fn ($app) =>
    new StationTenantResolver($app->make(TenantContext::class)));
```

Station resolves tenant from **hostname before authentication** (`ResolveTenant`
middleware), so policy is already known at the identifier step. No chicken-and-egg.

### 5.2 The problem tenancy introduces

Station's users are **global** — no `tenant_id` on `users`; `TenantMembership` is a
pivot, so one user may belong to many tenants with different policies.

If the session were simply "logged in," a user authenticating weakly at Tenant B
(email OTP) could then enter Tenant A (requires passkey + TOTP) at Tenant B's assurance
level. That is a silent posture downgrade.

### 5.3 Solution: sessions carry an Assurance Level, not a boolean

On successful authentication vouch records **what was actually satisfied** — which
factors, at what strength, at what time — and derives an `AssuranceLevel`, modeled on
NIST AAL and OIDC `acr`/`amr`.

The `RequireAssurance` middleware compares the session's level against the resolved
tenant's requirement:

```
session AAL ≥ requirement  → proceed
session AAL <  requirement  → step-up challenge, then proceed
```

This is not new machinery — it is the step-up flow needed anyway for sensitive actions.
Tenancy becomes another consumer of it. Cross-tenant navigation works without re-login
when the posture already qualifies, and cannot work when it does not.

**Recency is part of the level.** Policy can require `possession_strong within 12h`, so
a stale strong factor still triggers step-up.

### 5.4 Membership is authorization, not authentication

vouch answers *"is this person who they claim, to a sufficient standard?"*
`TenantMembership` answers *"may they be here?"*

vouch exposes a `TenantMembershipGate` contract so it can fail fast on a suspended
membership, but does not own membership, roles, or Spatie permissions.

Station's `TenantInvitation` gains an optional partner rather than a replacement: JIT
provisioning from a verified IdP claim can create membership without an invitation,
governed by the connection's JIT rules.

### 5.5 Pluggable audit sink

Station already runs `spatie/laravel-activitylog`. vouch ships an `AuditSink` contract
with three drivers: `activitylog`, `attest`, `null`. **`attest` is the compliance-grade
option, not a hard dependency.** An app may run more than one sink.

---

## 6. Surfaces and flows

### 6.1 Platform target

Laravel 13 only, PHP 8.4+. No version matrix. Fortify and `laravel/passkeys` are plain
dependencies at current versions.

Station's Laravel 13 upgrade gates *Station adoption*, not vouch development. Sluice
(already 13.8) is the first consumer.

### 6.2 Four surfaces, one policy

vouch does **not** unify the authentication *flow* across surfaces — API access
legitimately requires a different flow, since a machine client cannot be prompted for a
TOTP code. vouch unifies the *policy*, and makes assurance portable across flows.

| Surface | Flow | vouch's role |
|---|---|---|
| **Interactive** (Filament panel, web) | multi-step challenge | Owns end to end: factors, policy, step-up. |
| **Token issuance** (login endpoint, "create API token" UI) | interactive, then mint | Governs the authentication preceding the mint. Stamps achieved assurance and factor list onto the token. |
| **API request** (bearer token) | single-shot presentation | No challenge. Evaluates the token's recorded assurance against the route requirement; refuses if insufficient. |
| **Machine/service identity** (Sluice `is_service`) | bearer token, no human | Factors are meaningless. Governed by token policy. Recorded as a machine actor in audit. |

**The vulnerability this closes:** token issuance is itself an authentication event. If
a panel requires TOTP but `POST /api/login` mints a Sanctum token on email + password
alone, that endpoint is a complete MFA bypass. Strong policy on one surface is worth
nothing while a weak surface issues equally powerful credentials.

Filament's own documentation confirms the fragmentation risk:

> MFA is only enforced within the Filament panel authentication flow; it does not
> automatically apply to other application authentication paths like API routes or
> custom login pages.

### 6.3 Assurance travels with the token

A token records the assurance level and factor list (`amr`) of the session that minted
it, and **can never exceed it**. `RequireAssurance` then works on API routes as an
authorization check rather than a challenge.

When an API request presents an insufficient token, vouch returns the
[RFC 9470](https://www.rfc-editor.org/info/rfc9470/) step-up challenge (IETF Standards
Track, September 2023), designed for exactly this:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="A higher assurance level is required",
  acr_values="vouch:aal2", max_age="3600"
```

The client learns what would satisfy the endpoint. Machine clients get a clean,
documented 401 rather than a redirect to a login page. `max_age` covers recency —
"your strong factor was six weeks ago and this endpoint wants one from the last hour" —
which a boolean `is_authenticated` cannot express.

`RequireAssurance` therefore has two response modes:

- **interactive** → redirect to step-up
- **non-interactive** → 401 with the RFC 9470 challenge

Same policy object, same assurance model, two renderings.

### 6.4 Enterprise SSO scope

**v1 speaks generic OIDC only**, covering Entra ID (Azure), Okta, Google Workspace,
Auth0, and Keycloak, plus adapters for WorkOS and Auth0 so anyone needing SAML
delegates it to a broker. Domain→connection mapping and JIT provisioning are included.

**SAML is deliberately deferred.** XML signature verification is a notorious
vulnerability class (XML signature wrapping), metadata and certificate rotation are
operationally painful, and native SAML would roughly double v1. It is added only on
demonstrated demand.

Social OAuth (Google, GitHub, Apple) ships via Socialite in v1.

---

## 7. Security posture

### 7.1 Enumeration posture

Policy-resolvable (`strict` | `friendly`), so a tenant can tighten it.

**`strict`** — the identifier step always advances to a challenge regardless of match;
unknown identifiers receive a decoy challenge that never validates; responses are
padded to a fixed time budget with constant-time comparison; registration always
answers "check your email" rather than "already taken"; reset always answers "if an
account exists…"; rate limits are identical for known and unknown identifiers.

**`friendly`** (default for internal apps) — states that the account does not exist and
offers registration. Still fully rate-limited.

**Documented honestly:** strict mode *reduces* enumeration; it does not eliminate it.
Email delivery, timing under load, and response-size side channels remain. The docs
state residual risk rather than claiming non-enumerability.

OTP-only and SSO-only modes are naturally enumeration-resistant, since the response is
identical either way.

### 7.2 SSO account linking — highest-risk surface in the package

This is where auth packages acquire pre-account-hijacking vulnerabilities. All rules
are enforced in core, not left to the host app:

1. **Identity key is `(connection_id, sub)` — never email.** Email is mutable at the IdP.
2. **Never auto-link on an unverified email.** Requires `email_verified: true` *and* the
   connection being on a per-provider trust list for that claim. Entra ID's `email`
   claim is unreliable; prefer `oid`/`sub`.
3. **Auto-link is opt-in per connection, off by default.** Default on collision: create
   an `auth_link_request` and require proof of control of the existing account.
4. **A new SSO login may never adopt a pre-existing unverified local account.**
   Quarantine, do not merge. This is the account pre-emption attack.
5. **Unlinking respects last-factor protection** (§7.3).
6. **Tenant-scoped** per §4.1.
7. **JIT provisioning** governed by connection rules: allowed domains, default role,
   whether membership auto-creates.
8. **OIDC hygiene, non-negotiable:** PKCE required; `state` and `nonce` verified;
   `iss`/`aud` checked; ID token signature verified with `alg:none` and HS256-confusion
   rejected; JWKS rotation handled; discovery document cached with TTL; clock skew
   bounded.

### 7.3 Recovery — the weakest link in any passwordless design

The attacker's easiest path into a passwordless account is the recovery flow.

- Recovery codes are hashed, single-use, generated at first strong-factor enrollment;
  regeneration invalidates all prior codes.
- **`RecoveryCodeFactor` never satisfies a policy alone.** It grants a *recovery-grace
  session* at a restricted assurance level that can reach only security settings, and
  forces enrollment of a real factor before becoming a normal session.
- **Last-factor protection:** a user cannot delete or disable their only remaining
  credential.
- **Admin-assisted recovery** is an explicit, audited tenant-admin action: mandatory
  audit record, notification to every registered identifier, and a configurable
  break-glass delay (24–72h default) so a hijack attempt becomes visible before it
  succeeds. Never silent.
- Email-based recovery is only as strong as the mailbox, so policy can forbid it
  outright for high-assurance tenants.

### 7.4 Rate limiting and abuse

Multi-dimensional and configurable: per identifier, per IP, per (IP, identifier), per
tenant, and global. Exponential backoff plus lockout with a documented unlock path.
Challenge attempt caps invalidate the **challenge**, not merely the attempt.

**OTP pumping and SMS toll fraud are first-class and on by default** — per-identifier
send caps, per-tenant spend ceilings, country allow-list, hard daily limit. This is an
active financial attack against exactly the OTP and MFA flows; shipping it opt-in would
be negligent.

A CAPTCHA/Turnstile hook exists as a contract. No provider is bundled.

### 7.5 Session and step-up

- Session ID regenerated on **every assurance-level increase**, not only at login.
- All other sessions invalidated on credential change or removal; always on password
  change.
- Attempt state lives server-side under an opaque handle; session data is never trusted
  for it.
- Remember-me tokens bind to a revocable device record and can never satisfy above
  `knowledge` strength.
- `RequireAssurance` middleware for routes; `Vouch::stepUp($level)` for imperative use.

### 7.6 Secrets

TOTP secrets and OIDC client secrets are encrypted at rest via the `encrypted` cast,
with documented `APP_KEY` rotation. OTP codes are stored hashed, never plaintext, never
logged.

The `AuditSink` contract runs a **tested redaction pass** — credential material must
never reach the audit chain. This matters doubly when that chain is tamper-evident and
permanent.

### 7.7 `SECURITY-MODEL.md`

Ships with the package. Enumerates what vouch defends against and, explicitly, what it
does not: compromised host, malicious tenant admin, mailbox takeover under email
recovery. Includes token issuance as an MFA bypass vector (§6.2) and the residual
enumeration risk (§7.1).

Compliance buyers ask for this document by name, and writing it early forces gaps into
the open.

---

## 8. Package structure

```
fissible/vouch            Core, headless. Contracts, drivers, policy resolver,
                          state machine, ScreenSpec, JSON endpoints, Artisan
                          commands. Zero UI dependencies.

fissible/vouch-ui         All presentation. Adapters enabled by config; each
                          adapter's dependencies are `suggest`-ed, not required,
                          so a Filament-only app does not pull anything else.
```

Adapters live in **one** package rather than `vouch-filament`, `vouch-inertia`, … so
the presenter contract cannot drift between them and there is one version to release.
The cost is a heavier `suggest` block, which is acceptable.

### 8.1 The presenter layer

`vouch-ui` must not contain N parallel implementations of auth logic. Core exposes a
framework-agnostic `ScreenSpec`:

```php
final class ScreenSpec {
    public AuthStep $step;              // identify | challenge | enroll | recover | step_up
    public array $offeredFactors;       // [FactorOption] — id, label, strength, is_default
    public array $fields;               // [FieldSpec] — name, type, autocomplete, constraints
    public ?ChallengePayload $payload;  // WebAuthn options, OTP delivery hint, OIDC redirect
    public array $errors;               // posture-filtered — never leaks enumeration
    public ?RetryPolicy $retry;         // lockout/backoff state, if disclosable
}
```

Every adapter is **rendering only**. All security-relevant decisions — which factors to
offer, what an error may say, whether a retry is permitted — happen once, in core,
under test. Adding an adapter is a template exercise, which is what makes supporting
multiple UI stacks tractable rather than a scope bomb.

This is the same principle as §6.3's two response modes: decide once in core, render
per surface.

### 8.2 v1 adapters

**Filament v5** and **Blade/Livewire**.

Filament covers Station and Sluice completely; Blade/Livewire covers any plain Laravel
app. Two adapters validate the `ScreenSpec` contract against genuinely different
rendering models before it is committed to publicly — the second adapter is what
reveals what the first one baked in wrongly.

Inertia React and Inertia Vue follow in v1.1. Cheap to add once the contract has proven
itself; expensive to redesign.

### 8.3 Filament strategy: replace the flow, do not plug into it

Filament v5 has its own MFA (`->multiFactorAuthentication([AppAuthentication::make(),
EmailAuthentication::make()], isRequired: true)`) and an extensible provider contract.

| | Approach | Verdict |
|---|---|---|
| **A** | Implement Filament's `MultiFactorAuthenticationProvider` backed by vouch factors; Filament keeps driving its login page. | Least invasive, but Filament decides ordering and enforcement, so vouch's policy engine, assurance levels, and enumeration posture only partially apply. Reintroduces the split Filament's own docs warn about. |
| **B** | Swap Filament's auth pages (`$panel->login(...)`, `->passwordReset(...)`); disable Filament's MFA; hand Filament an authenticated session with the assurance level attached. | **Default.** One posture, one policy engine, panel and non-panel routes governed identically. Cost: tracking Filament's page APIs across minor versions. |

Ship **B** as the default; keep **A** documented as a "light mode" for apps that want
Filament's flow intact.

---

## 9. Testing strategy

Per the fissible process rule on validating IO, timing, and terminal behavior against
reality rather than theory:

- **Factor contract suite** — one shared test trait every driver must pass: enroll,
  challenge, verify, revoke, replay resistance, expiry. A new driver is done when the
  suite is green.
- **Policy precedence matrix** — table-driven across global → tenant → role → user,
  including conflicting requirements.
- **Assurance-level matrix** — cross-tenant navigation in both directions
  (strong→weak, weak→strong), plus recency expiry.
- **Enumeration tests with teeth** — strict mode must yield byte-identical responses and
  bounded timing variance between known and unknown identifiers, asserted statistically
  rather than smoke-tested.
- **Security regression suite** — every vulnerability class gets a permanent test:
  replay, `state`/`nonce` tampering, `alg:none`, cross-tenant OIDC subject reuse,
  pre-account-hijack, last-factor deletion, recovery-grace escalation, token-issuance
  MFA bypass.
- **Real dependencies, not mocks** — Mailpit for mail, containerized Keycloak for OIDC,
  a virtual authenticator in Dusk for actual WebAuthn ceremonies.
- **Dusk** for Filament and Blade adapter flows.
- **Mutation testing (Infection)** scoped to the policy resolver and factor verification
  paths — the two places where a silently inverted condition is catastrophic rather than
  merely wrong.

Stack: Pest + Orchestra Testbench, Laravel 13 / PHP 8.4.

---

## 10. Open items for the implementation plan

These are settled in principle but need decisions during planning, not before:

1. **Repository creation.** `fissible/vouch` and `fissible/vouch-ui` do not exist yet.
   Both need the standard fissible wiring: `VERSION`, `release.sh`, `.cliff.toml`, CI
   and release workflows, and — per the known-issues note — the `FISSIBLE_PAT` Actions
   secret added per-repo before first CI run.
2. **CI workflow.** The org's reusable `test-bash.yml` is bash-oriented. These are PHP
   packages and need a PHP/Pest CI workflow, which the org does not yet have a reusable
   template for.
3. **Assurance level vocabulary.** Whether to use NIST AAL1/2/3 names, OIDC `acr` URIs,
   or a vouch-specific scale. Affects the `acr_values` string in §6.3.
4. **Sluice `is_service` integration detail.** Exact seam between vouch's
   `ServiceIdentity` contract and Sluice's existing flag.
5. **Station Laravel 13 upgrade** must land before Station can adopt.

---

## 11. Decision log

| Decision | Choice | Rationale |
|---|---|---|
| Build posture | Orchestration layer over existing primitives | "Security first" and "reimplement crypto" are contradictory. Smallest CVE surface, fastest secure v1. |
| Positioning | Compliance-grade auth with attest audit trail | Only defensible moat; the ergonomic-all-in-one space is already contested by devdojo/auth and the starter kits. |
| Enterprise SSO scope | OIDC only + broker adapters | SAML is the single largest scope and vulnerability risk. Brokers cover it. |
| Policy scope | Per-tenant, resolvable chain | Required by Station; retrofitting tenancy touches the whole schema. |
| Package surface | Headless core + separate UI package | Station and Sluice have existing UIs; opinions must be optional. |
| UI adapters (v1) | Filament v5 + Blade/Livewire | Covers both first consumers; two adapters validate the presenter contract. |
| Filament integration | Replace auth pages (B), not plug into MFA (A) | Plugging in reintroduces the policy fragmentation vouch exists to remove. |
| Platform | Laravel 13 / PHP 8.4 only | Station upgrade in progress; removes the CI matrix entirely. |
| API auth | Different flow, same policy; RFC 9470 for refusal | Machine clients cannot be challenged. Unify policy, not flow. |
