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

- **vouch does not implement API token storage, scoping, or transport.** Sanctum keeps
  that. vouch **does** own the issuance gate and the assurance record bound to each
  token (§6.5). The boundary is narrower than "Sanctum owns tokens" — an earlier draft
  of this spec stated the wider boundary and was unimplementable as a result.
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
| `OidcFactor` | `facile-it/php-openid-client` for protocol; Socialite for social providers | inherited from IdP |
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
    'mfa'          => ['any_of' => [
                           // A user-verified passkey is a multi-factor authenticator.
                           ['all_of' => [['factor' => 'passkey', 'user_verified' => true]]],
                           // Otherwise require independent knowledge and possession.
                           ['all_of' => ['password', 'totp'],
                            'require_distinct_credentials' => true,
                            'require_independent_authenticators' => true],
                       ]],
    'sso'          => ['step1' => ['oidc'], 'step2' => 'defer_to_idp'],
    'passwordless' => ['step1' => ['passkey','email_otp'], 'step2' => false],
],
```

An app sets `'mode' => 'mfa'` and is done. An app with real requirements writes a
policy document instead. **A preset *is* a policy document** — same engine, no second
code path.

### 3.6 Satisfiability is a structured predicate, not a strength comparison

An ordered strength enum alone is insufficient, and gets the count wrong in both
directions.

**Under-counts:** a user-verified passkey is *itself* a multi-factor authenticator —
possession of the authenticator plus a biometric or PIN. NIST treats it as AAL2. A
policy that mechanically demands "two steps" would force a pointless second factor on
the strongest credential available.

**Over-counts:** a flat "offer passkey at step 1 and step 2" policy — the shape an
earlier draft of the `mfa` preset used — lets two assertions from the *same* passkey
count as two factors. They are one authenticator. Nothing in a strength comparison
prevents it, which is why §3.5's preset now expresses the requirement as `any_of` /
`all_of` over explicit predicates rather than as an ordered pair of steps.

Satisfiability is therefore evaluated over a structured record of what actually
happened. Each satisfied factor contributes:

| Attribute | Purpose |
|---|---|
| `credential_id` | Distinctness. Two satisfactions sharing a credential ID are one factor. |
| `factor_kind` | `knowledge` / `possession` / `inherence`. |
| `is_multi_factor` | True for user-verified passkeys — the credential alone spans two kinds. |
| `user_verified` | Whether UV was actually asserted, not merely requested. |
| `phishing_resistant` | True for WebAuthn; false for OTP, TOTP, password. |
| `authenticator_id` | Independence — distinct credentials on the same authenticator are not independent. |
| `satisfied_at` | Recency, per §5.3. |

Policy predicates are then explicit:

- `require_distinct_credentials` — no credential ID may satisfy more than one step.
- `user_verified` — used in an explicit alternative branch when a UV passkey alone is
  permitted to satisfy a multi-factor requirement. It is never a global override of a
  branch that requires distinct credentials.
- `require_phishing_resistant` — for high-assurance tenants; excludes every OTP form.
- `require_independent_authenticators` — stricter than distinct credentials; two
  passkeys on the same device do not count as two.

`recovery`-strength satisfactions never contribute to a policy (§7.3).

**A policy chooses a satisfying branch; it does not combine contradictory flags.** The
`mfa` preset above has two alternatives: one user-verified passkey, *or* password plus
an independent TOTP credential. Selecting and completing either branch authenticates
the attempt. A passkey is never silently counted twice, and an app that wants to forbid
the single-passkey branch removes that branch rather than relying on predicate
precedence. The UI is derived from the candidate branches: after a verified passkey it
completes; after a password it offers TOTP. This makes the security decision and the
screen sequence the same decision.

---

## 4. Data model

Nothing is added to `users`. Adoption touches zero existing columns.

| Table | Scope | Purpose |
|---|---|---|
| `auth_identifiers` | user | email / phone / username → user. `verified_at`, `is_primary`. Enables multiple emails per user, which SSO linking requires. |
| `auth_credentials` | **user, + `relying_party_id` where applicable** | Password hash, TOTP secret, WebAuthn credential. `last_used_at`, `disabled_at`, strength snapshot, plus the §3.6 attributes (`is_multi_factor`, `user_verified`, `phishing_resistant`, `authenticator_id`). **Not** federated identities — see below. |
| `auth_federated_identities` | **tenant, via connection** | Dedicated table for OIDC/social identities. Non-null `connection_id` FK, `issuer`, `subject`, claim snapshot. **Unique constraint on `(connection_id, issuer, subject)`.** |
| `auth_challenges` | attempt | Hashed OTPs. `expires_at`, attempt counter, IP/UA binding, `consumed_at`. |
| `auth_attempts` | request | The state machine. Single authoritative store, versioned transitions — see §4.3. |
| `auth_token_assurances` | token | Assurance record bound to an issued Sanctum token. See §6.5. |
| `auth_policies` | **tenant** | Policy-as-data. Deliberately shaped like Sluice's gate engine so the two read alike. |
| `auth_connections` | **tenant** | Tenant ↔ IdP: email domain, OIDC discovery URL, client credentials, claim mappings, JIT provisioning rules. |
| `auth_link_requests` | user | Pending SSO ↔ existing-account links awaiting proof of control. |

Federated identities get their own table rather than a polymorphic row in
`auth_credentials` because the two have incompatible scoping and integrity rules: a
credential is the user's, a federated identity belongs to a tenant's connection, and
the `(connection_id, issuer, subject)` uniqueness must be a database constraint rather
than a driver convention. §7.2 rule 1 is unenforceable otherwise.

### 4.1 Scope split rationale

- **Origin-bound credentials carry a relying-party ID.** WebAuthn credentials are bound
  by the browser to the RP ID they were registered against; a passkey enrolled at
  `acme.com` is cryptographically unusable at `beta.station.app`. Station resolves
  tenants by custom apex domain first (`ResolveTenant` matches `Tenant::where('domain',
  $host)` before falling back to subdomain), so tenants genuinely live on separate
  origins. `auth_credentials.relying_party_id` is therefore part of credential lookup
  for WebAuthn. A user in two custom-domain tenants enrolls a passkey per origin.
- **Origin-free credentials remain global to the user.** Passwords and TOTP secrets are
  not origin-bound and are shared across every tenant the user belongs to.
- **Federated identities are tenant-scoped, enforced by constraint.** An OIDC subject
  from Acme's Okta must satisfy *only* Acme's tenant. **Getting this wrong is a
  cross-tenant account takeover**, so it is a unique index, not a convention (§4).

An earlier draft asserted that all credentials were global. That is false for WebAuthn
under custom domains and would have produced a passkey flow that silently fails on
every tenant except the enrolling one.

### 4.2 Migration compatibility

Existing `users.password` hashes are read through a compatibility shim and migrated
lazily on next successful login. Station's `users.app_authentication_secret` migrates
to an `auth_credentials` row of type `totp`. `php artisan vouch:backfill` performs a
one-shot migration. **No existing column is dropped in v1.**

### 4.3 `auth_attempts` persistence contract

The attempt state machine is security-sensitive, so "cache-backed with a DB fallback"
is not an acceptable description — two stores for one attempt permits split-brain
transitions, replay across a cache eviction, and double-consumption of a challenge
under concurrent requests.

The contract is:

- **One authoritative store per attempt**, chosen by config and never mixed within an
  attempt's lifetime. Audit is an append-only *side effect*, never a fallback state
  store.
- **Compare-and-swap transitions** against a monotonic `version` column. A transition
  computed from version *n* may only be written if the stored version is still *n*.
  Losing writers re-read and retry or fail closed; they never overwrite.
- **Atomic consume-on-success.** Marking a challenge consumed and advancing the attempt
  are a single atomic operation, so a concurrent duplicate submission cannot both
  succeed.
- **Bound context.** Each attempt records the session/browser context it was created
  under and refuses transitions presented from a different one.
- **Hard expiry** independent of cache TTL, enforced on read.

Cache-backed and database-backed drivers both implement this; the cache driver requires
atomic CAS primitives (Redis `WATCH`/Lua), which excludes the array and file cache
stores from production use. That exclusion is enforced at boot, not documented and
hoped for.

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
Tenancy becomes another consumer of it.

**Recency is part of the level.** Policy can require `possession_strong within 12h`, so
a stale strong factor still triggers step-up.

#### 5.3.1 Assurance is per-origin, not portable across custom domains

Assurance travels with the session, and a session cookie set on `acme.com` is never
sent to `beta.station.app`. Station's custom-domain tenants therefore occupy separate
browser origins with **separate sessions and separate assurance state**. The same
boundary that scopes passkeys by relying-party ID (§4.1) scopes assurance.

Concretely:

- Tenants sharing a parent domain (`*.station.app`) can share a session cookie, and
  assurance carries between them. Entering a stricter tenant triggers step-up rather
  than re-login.
- Tenants on custom apex domains cannot. Each is an independent authentication context;
  the user authenticates per origin.

An earlier draft claimed cross-tenant navigation without re-login as a general
capability. It is not achievable across origins without a central authentication origin
and a signed-assertion handshake — effectively making Station its own IdP. That was
evaluated and **deliberately rejected for v1** as disproportionate scope; see §11.

The downgrade risk that motivated assurance levels (§5.2) is unaffected — it was always
a *within-session* problem, and within a session assurance is still enforced per tenant.

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
authorization check rather than a challenge. §6.5 specifies how that record is created
and enforced — without a mandatory issuance integration this guarantee is unbacked.

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

**The validating component is named, not implied.** Socialite is an OAuth2 client for
named providers; it performs no discovery, no JWKS handling, and no ID-token
validation. Attributing the §7.2.8 guarantees to "Socialite + generic OIDC discovery"
would have hidden exactly the protocol work this package promises not to write itself.

v1 pins **`facile-it/php-openid-client`** (1.0.0, 2026-06-12, PHP ^8.2) as the owner of
discovery, JWKS refresh, and ID-token signature and claim validation. Socialite's
official role is limited to Google and GitHub. **Sign in with Apple** uses the named,
maintained community adapter **`socialiteproviders/apple` ^5.10** via
`socialiteproviders/manager` ^4.4; it is an optional `vouch-ui` dependency enabled only
when Apple is configured. This is preferable to writing an adapter: Apple needs a
rotating signed client-secret JWT and has provider-specific callback behavior, neither
of which belongs in vouch's protocol surface.

**Gate:** the pin reached 1.0.0 only two months before this spec. Before it becomes
load-bearing, the implementation plan must include an evaluation task — maintenance
cadence, issue responsiveness, audit history, and a review of its signature-validation
path against the §7.2.8 checklist. If it fails that evaluation, the fallback is audited
per-provider adapters plus WorkOS/Auth0 brokers, and the generic-OIDC claim is dropped
from v1.

**SAML is deliberately deferred.** XML signature verification is a notorious
vulnerability class (XML signature wrapping), metadata and certificate rotation are
operationally painful, and native SAML would roughly double v1. It is added only on
demonstrated demand.

### 6.5 Token issuance is a mandatory integration, not an advisory one

`RequireAssurance` cannot reconstruct assurance at request time — the authenticating
session is long gone, and its factors were never recorded against the token. Assurance
must be captured **at mint time** or it does not exist.

Sluice demonstrates the problem: `app/Filament/Pages/ApiTokens.php:64` and
`app/Console/Commands/SluiceToken.php:48` both call `createToken()` directly on the
model, with no interception point available to a middleware.

The contract:

1. **`auth_token_assurances`** records, per issued token: assurance level, factor list
   (`amr`), credential IDs, issuing session ID, and `issued_at`. Keyed to the Sanctum
   `personal_access_token` ID with a cascading delete.
2. **`Vouch::issueToken()`** is the supported issuance path. It performs the policy
   check for the `token_issue` intent, mints via Sanctum, and writes the assurance
   record in the same transaction.
3. **Default deny.** A presented token with no assurance record is rejected by
   `RequireAssurance`, not treated as unknown-but-acceptable. Any `createToken()` path
   that bypasses vouch produces an unusable token, so the failure is loud at
   development time rather than silent in production.
4. **Pre-existing tokens are reissued, never adopted.** Tokens minted before vouch was
   installed have no observed assurance, and backfilling one would be asserting a fact
   nobody witnessed — precisely the kind of unverifiable claim this package exists to
   eliminate. There is no adopt command. On adoption, existing tokens are revoked and
   holders reissue through `Vouch::issueToken()`. Sluice's current tokens go through
   this, and the migration guide states the operational cost plainly rather than
   offering a shortcut around it.
5. **Machine tokens** (`is_service`) are issued with an explicit `machine` assurance
   marker rather than a human factor list, satisfy only routes that permit machine
   actors, and are recorded as machine actors in audit (§6.2).
6. **Revocation on credential change.** Removing or disabling a credential revokes
   every token whose assurance record cites that credential ID. Password change revokes
   all human tokens by default. Both are configurable but default to the safe side.
7. **Call-site enforcement.** Sluice's two `createToken()` sites are rewritten to
   `Vouch::issueToken()` as part of adoption; the package ships a `vouch:audit-tokens`
   command that greps for direct `createToken()` use and fails CI.

Social OAuth ships in v1: Google and GitHub via official Socialite drivers, and Apple
via `socialiteproviders/apple`.

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

#### 7.1.1 Strict mode is specified per flow

An earlier draft called OTP-only and SSO-only flows "naturally enumeration-resistant."
That is wrong: conditional message delivery and domain→connection lookup both leak, and
a naive decoy leaks worse. Strict mode defines behavior per factor.

**Email / SMS OTP.** The screen, status code, and response body are identical for known
and unknown identifiers, and the response is held to a fixed time budget.

**A decoy challenge never sends a message to an attacker-supplied recipient.** For an
unknown identifier, nothing is dispatched; a challenge record is created that cannot
validate. Sending "something" to unknown addresses would turn the login form into a
spam and toll-fraud amplifier — the §7.4 attack, self-inflicted. The consequence is an
accepted, documented residual channel: the attacker learns nothing from the response
but may infer from non-delivery. Reducing on-screen leakage while adding a delivery
amplifier would be a net loss.

**SSO / domain→connection lookup.** Whether an email domain maps to a configured
connection reveals tenant existence and enterprise-customer identity. It is impossible
to conceal that fact end-to-end once a known connection redirects the browser to its
real IdP: an unknown connection has no equivalent safe destination. Strict mode
therefore guarantees only that the **identifier endpoint** is observably identical for
known and unknown domains. It creates an opaque attempt and routes both responses to
the same local continuation URL; it does not disclose connection metadata or an IdP
target at that point.

Starting federation is a separate, user-initiated continuation. At that step, the
configured IdP redirect is intentionally observable and is documented as residual
enterprise-connection enumeration risk. The continuation must be bound to the opaque
attempt, allow only the connection's registered redirect URI, and fail generically for
an unknown domain; it must never become an open redirect. A central broker cannot
remove this browser-visible distinction without acting as a separate identity provider,
which is out of scope for v1.

**Registration and reset** always answer "check your email," per the main rule above.

**Testable definition.** For the identifier endpoint, "observably identical" means
byte-identical response bodies, identical status codes and header sets, and timing
variance within a configured bound — asserted statistically in the test suite (§9), not
judged by eye. Federation-continuation tests instead prove opaque-attempt binding,
generic unknown-domain failure, and rejection of arbitrary redirect targets.

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
does not.

Out of scope: compromised host, malicious tenant admin, mailbox takeover under email
recovery.

Documented residual risks, each traceable to a decision in §11:

| Risk | Section |
|---|---|
| Token issuance as an MFA bypass vector, and the default-deny mitigation | §6.5 |
| Enumeration via message non-delivery, or an IdP redirect after federation begins, in strict mode | §7.1.1 |
| No assurance portability across custom-domain tenants; users authenticate per origin | §5.3.1 |
| Passkeys require per-origin enrollment for multi-tenant users on custom domains | §4.1 |
| Generic OIDC security inherited from a pinned third-party client | §6.4 |
| Adopted pre-vouch tokens carry asserted, not observed, assurance | §6.5 item 4 |

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

### 8.1 The `Vouch\Kernel` boundary

vouch is a Laravel package, and unapologetically so — its value *is* the orchestration
of Laravel primitives. There is no framework-agnostic `PasskeyFactor`, because the thing
it exists to wrap is `laravel/passkeys`. Every driver, the Sanctum issuance gate, the
middleware, the migrations, and the cache CAS in §4.3 are all correctly Laravel-bound.

But the decision logic is not, and it is where the risk concentrates:

| Layer | Contents | Dependencies |
|---|---|---|
| `Vouch\Kernel` | `FactorStrength`, `FactorKind`, the §3.6 satisfiability predicate, the §3.3 resolution chain, `AuthAttempt` *transition rules* (not persistence), `AssuranceLevel` derivation and recency, `ScreenSpec` construction, policy document parsing and validation, enumeration response shaping | `php`, `psr/clock`. **Nothing else.** |
| `Vouch\*` (rest) | Drivers, persistence, HTTP, container wiring, Artisan, Sanctum integration | `illuminate/*`, Fortify, `laravel/passkeys`, Socialite, Spatie OTP, `facile-it/php-openid-client` |

The kernel is roughly 20–30% of the code and close to 80% of the risk — every place a
silently inverted condition is catastrophic rather than merely wrong. `psr/clock` is its
only dependency so recency logic is testable without freezing global time.

`ScreenSpec` qualifies for the kernel **only while it remains immutable, framework-free
data**. The moment it acquires a rendering concern, a Blade or Filament type, or
mutability, it belongs outside. Rendering adapters stay in `vouch-ui` (§8.2)
unconditionally.

**Enforcement.** A CI architecture test asserts that nothing under `Vouch\Kernel`
imports or calls:

- `Illuminate\*`, any Laravel facade, or a global helper (`app()`, `config()`,
  `now()`, `event()`, …)
- any Eloquent type, or any driver namespace
- **global time** — `time()`, `microtime()`, `date()`, or a bare
  `new DateTimeImmutable()`

Time enters only through an injected `Psr\Clock\ClockInterface`. This is a build
failure, not a convention.

**Extraction trigger — evidence-based, not scheduled.**

> `Vouch\Kernel` is an architecture-enforced pure-PHP namespace in v0.x. It is extracted
> to `fissible/vouch-kernel` when it has a second consumer, or when its public API has
> demonstrated stability through a full release cycle. Extraction remains a
> precondition for any non-Laravel support claim.

An earlier draft committed extraction to v1.0. That is the worst available moment: v1.0
is where public API stability is *declared* under semver, so performing the most
disruptive packaging change available at exactly that point maximises downstream churn
— and it treats the declaration of stability as though it were evidence of it.

**Measuring the stability trigger.** "Demonstrated stability" is otherwise a judgment
call that resolves to "not yet" indefinitely. It is made checkable: the kernel's public
API surface is captured as a committed snapshot, and the trigger is met when a full
minor release cycle closes with no breaking change to that snapshot. Reviewed at each
minor release, not left to notice itself.

Note that the two triggers partly collapse. Station and Sluice are both Laravel and
would consume `fissible/vouch`, not the kernel — so a second *kernel* consumer means
non-Laravel adoption, which is the same condition as the support claim. The
load-bearing trigger in practice is API stability.

**Naming discipline.** `fissible/vouch` is a Laravel package. `Vouch\Kernel` is an
internal pure-domain boundary and is **not** evidence that the package is
framework-neutral; no documentation, README, or Packagist description may imply
otherwise before extraction. Calling the Laravel package "core" in contrast to the UI
package is a layering statement, not a portability claim.

Holding the kernel as a namespace boundary through v0.x buys the fast mutation testing
and the small auditable surface immediately, without paying a cross-package version bump
on every kernel change while the API is still moving. The arch test keeps eventual
extraction mechanical rather than an untangling exercise. It ends at the
`fissible/attest` (pure) and `fissible/attest-laravel` (adapter) shape — arrived at on
evidence rather than on a date.

### 8.2 The presenter layer

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

### 8.3 v1 adapters

**Filament v5** and **Blade/Livewire**.

Filament covers Station and Sluice completely; Blade/Livewire covers any plain Laravel
app. Two adapters validate the `ScreenSpec` contract against genuinely different
rendering models before it is committed to publicly — the second adapter is what
reveals what the first one baked in wrongly.

Inertia React and Inertia Vue follow in v1.1. Cheap to add once the contract has proven
itself; expensive to redesign.

### 8.4 Filament strategy: replace the flow, do not plug into it

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
  rather than smoke-tested. The SSO continuation is tested separately for opaque-attempt
  binding, generic unknown-domain failure, and rejection of arbitrary redirects.
- **Security regression suite** — every vulnerability class gets a permanent test:
  replay, `state`/`nonce` tampering, `alg:none`, cross-tenant OIDC subject reuse,
  pre-account-hijack, last-factor deletion, recovery-grace escalation, token-issuance
  MFA bypass, token surviving revocation of its cited credential, and one credential
  satisfying both steps of a two-factor policy.
- **Concurrency suite for `auth_attempts`** (§4.3) — parallel submissions of the same
  challenge must produce exactly one success; CAS transitions under contention must
  never interleave; expiry must be enforced on read regardless of cache state.
- **Relying-party scoping** — a passkey enrolled under one RP ID must not be offered or
  accepted under another, asserted against both a custom-domain and a subdomain tenant.
- **Real dependencies, not mocks** — Mailpit for mail, containerized Keycloak for OIDC,
  a virtual authenticator in Dusk for actual WebAuthn ceremonies.
- **Dusk** for Filament and Blade adapter flows.
- **Mutation testing (Infection)** scoped to `Vouch\Kernel` — the policy resolver,
  satisfiability predicate, and assurance derivation. Because the kernel boots no
  framework (§8.1), this pass runs fast enough to stay in CI rather than being nominally
  configured and quietly skipped.
- **Architecture test** asserting nothing under `Vouch\Kernel` imports `Illuminate\*` or
  a driver namespace. A build failure, not a convention.

Stack: Pest + Orchestra Testbench, Laravel 13 / PHP 8.4. Kernel tests run under plain
Pest with no Testbench boot.

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
6. **`facile-it/php-openid-client` evaluation** (§6.4) is a gating task, not a
   formality. If it fails, generic OIDC leaves v1.
7. **Central authentication origin** remains the only path to cross-origin assurance
   portability and single-enrollment passkeys. Rejected for v1 (§11); revisit if
   custom-domain tenants with multi-tenant users become a real support burden.
8. **Kernel extraction** (§8.1) is triggered by evidence, not schedule. Two planning
   tasks follow from that: capturing the kernel's public API surface as a committed
   snapshot from the first release, and adding a standing "is the trigger met?" check
   to the minor-release procedure so it cannot quietly never happen.

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
| Token issuance | Mandatory vouch-owned gate + default-deny assurance record | Assurance cannot be reconstructed at request time. Sluice mints tokens at two uninterceptable call sites, so an advisory boundary would have left the MFA bypass open. |
| WebAuthn scoping | Credentials carry a relying-party ID | Station resolves tenants by custom apex domain, and WebAuthn binds credentials to an RP ID. Global passkeys would silently fail on every tenant but the enrolling one. |
| Cross-origin assurance | **Dropped from v1** | Session cookies do not cross apex domains. Achievable only via a central authentication origin, which would make Station its own IdP — disproportionate scope for v1. Tenants under a shared parent domain retain it. |
| Two-factor satisfiability | Structured predicate, not strength ordering | Ordering both under-counts UV passkeys (genuinely AAL2 alone) and over-counts one credential used twice. |
| Federated identity storage | Dedicated table, unique `(connection_id, issuer, subject)` | The §7.2 tenancy invariant must be a database constraint; a polymorphic credential row leaves it to driver convention. |
| Attempt persistence | Single authoritative store, CAS transitions | Dual-store "cache with DB fallback" permits split-brain, replay, and double-consumption. |
| OIDC protocol owner | Pin `facile-it/php-openid-client`, gated on evaluation | Socialite does no discovery, JWKS, or ID-token validation. The "we don't implement protocols" boundary needs a named component behind it. |
| Pre-vouch tokens | Reissue, never adopt | Backfilling an assurance record asserts a fact nobody observed. No adopt command ships, so the shortcut cannot be taken under deadline pressure. |
| Kernel boundary | `Vouch\Kernel` namespace in v0.x, arch-test enforced | The kernel is ~20–30% of the code and ~80% of the risk, and needs to be fast to mutation-test. Deferring the package split avoids daily cross-package version bumps while the API churns; the arch test keeps extraction mechanical. |
| Kernel extraction trigger | Second consumer, or API stable across a full minor cycle measured against a committed surface snapshot — **not** a scheduled v1.0 split | v1.0 is where API stability is declared, not demonstrated; splitting there maximises downstream churn at the worst moment. Extraction is a precondition for any non-Laravel support claim. |
| Kernel time access | Injected `Psr\Clock\ClockInterface` only; global time functions banned by the arch test | Recency logic (§5.3) is security-relevant and must be deterministic under test without freezing global time. |
| MFA preset semantics | Explicit `any_of` branches | A user-verified passkey is an alternative to, not a second assertion within, password-plus-TOTP MFA. This removes predicate precedence as a security decision. |
| Strict SSO enumeration | Identical identifier endpoint; documented federation-stage leakage | A real IdP redirect is necessarily visible. Hiding it requires becoming a separate identity provider, which v1 does not do. |
| Apple social login | `socialiteproviders/apple` ^5.10 | Maintained adapter over Socialite's manager covers Apple's provider-specific signed client secret and callback behavior without expanding vouch's protocol surface. |
