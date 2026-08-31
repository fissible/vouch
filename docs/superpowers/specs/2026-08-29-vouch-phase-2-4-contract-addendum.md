# Vouch 2.4 — contract addendum

**Date:** 2026-08-29
**Status:** required before implementation
**Extends:** [`2026-08-28-vouch-phase-2-4-token-gate-design.md`](2026-08-28-vouch-phase-2-4-token-gate-design.md)

The design was approved for planning with the observation that its prose could be
satisfied by an implementation that weakens the guarantee. This addendum replaces prose
with contracts, in the five places where that was true.

## 1. Transaction ownership

`issue(ConnectionInterface $connection, TokenGrant $grant): IssuedToken`.

The driver MUST perform every write on `$connection`. This is not advisory: the Sanctum
adapter therefore CANNOT call `$user->createToken()`, which resolves the model's default
connection and would silently escape Vouch's transaction. It constructs the personal
access token on `$connection` explicitly.

An issuer that cannot join a caller-supplied transaction — a remote or HTTP-backed
issuer, say — returns `false` from `supportsTransactionalIssuance()` and is refused for
assurance-bound human tokens rather than silently downgrading the guarantee.

`issue()` performs no deferred or asynchronous persistence — no queued job, no
post-commit hook. An effect that lands after the transaction closes cannot be rolled back
with it, so it is outside the guarantee and therefore forbidden.

**Made structural by its test, not by this paragraph.** The contract test supplies a
genuinely separate transactional connection, calls `issue()`, then rolls the OUTER
transaction back after it returns, and asserts that every driver-owned persistent effect
is absent — not merely that the token row is gone. Observing one row at one failure point
would let a driver pass while emitting a side write or taking a different write path. The
test targets the contract, so every future driver inherits it.

## 2. Middleware and resolver ordering

`RejectsUnrecordedTokens` installs in `web` and `api`, plus the `vouch.token` alias for
other groups. It does NOT assume `auth:sanctum` has run, and does not read headers.

For each registered issuer, in configured order, it calls
`resolveForRequest(Request): ?ResolvedToken`. The contract of that method is **"I
authenticated the effective principal of this request"** — not "I can parse a credential
out of it". That phrase is only useful if it is decidable, so the Sanctum driver's rule is
written out exactly rather than described:

1. Resolve through the same `sanctum` guard `auth:sanctum` will use. No principal → return
   `null`.
2. Take the principal's `currentAccessToken()`. Sanctum attaches a `TransientToken` when it
   authenticated a *cookie* principal, and only falls back to bearer validation when no
   session principal exists. A `TransientToken`, or none, → return `null`.
3. Claim only a real configured `PersonalAccessToken`, and verify its tokenable is the
   resolved principal.

This is why the guard never reads the `Authorization` header: a request can carry a bearer
header while Sanctum legitimately selects the cookie actor, and header-sniffing would
reject it.

| Request | Resolver outcome | Guard |
|---|---|---|
| Cookie-authenticated SPA (Sanctum stateful) | Sanctum driver returns `null` — it authenticated a session, not a token | passes through; session assurance applies as today |
| Sanctum bearer token | Sanctum driver returns a `ResolvedToken` | requires an assurance record |
| Passport / JWT / unrelated bearer | no registered issuer claims it | passes through untouched |
| Bearer header present but Sanctum chose the cookie actor | Sanctum driver returns `null` | passes through — this is why headers are not read |
| Two issuers both claim it | — | `RuntimeException` naming both |

The last row is a configuration error, not an authentication outcome, so it is loud rather
than a 401. **Answering the question directly: no, not every `api` route requires a
Vouch-recorded token.** Default-deny applies if and only if the request is
token-authenticated. Cookie-authenticated API traffic is unaffected.

## 3. Persisted proof and recency semantics

**Amended.** An earlier draft defined the selected proof as "the exact
`SatisfiedFactor` set the policy evaluation used to reach the required level".
Measuring that against the real evaluator showed it produces an availability
regression: for `any_of: [all_of: [totp], all_of: [password, totp]]`, a user who
presents password AND totp has the password discarded, because depth-first
search satisfies the cheaper branch first. Their login records `aal1` and loses
every `aal2` route, on an implementation detail of the solver.

Assurance describes what the user actually proved during authentication; the
policy decides the minimum proof required for admission. A policy's cheapest
satisfying branch must not discard additional credentials the user successfully
presented. So:

- Persist **every factor satisfied during the successful authentication
  attempt**.
- Exclude factors merely available, historical, failed, or presented outside
  that attempt.
- Derive `acr` from that complete immutable set.
- Set recency from the **oldest** factor in the set, so extra evidence cannot
  weaken freshness checks.
- Keep the proof subject-bound and transactionally persisted with the session.

`AuthSuccess::$factors` is already scoped to a single attempt, so the concern the
original wording was reaching for — a policy inflated by factors accumulated in
other sessions or at other times — is met without discarding evidence the user
genuinely presented. The evaluator's narrower `Verdict::$usedFactors` is not
persisted; `tests/Kernel/SelectedFactorSubsetTest.php` pins the fact that the
two sets can differ, so this decision cannot quietly become a no-op.

Recency then follows:

- `weakest_satisfied_at` = `MIN(satisfied_at)` across the persisted proof.
- `max_age` is satisfied iff `weakest_satisfied_at >= now - max_age`, in UTC,
  using the injected `ClockInterface`. No `now()` helper, no ambient timezone.
- A missing or null `satisfied_at` is rejected at **deserialization**, before any
  level or recency evaluation. `SatisfiedFactor::$satisfiedAt` is a non-nullable
  `DateTimeImmutable`, so the type cannot carry the case at all; an earlier draft
  claimed this rule "matches the Kernel's empty-evidence guard", which conflated
  two different things — the Kernel's null is `weakestSatisfiedAt === null`,
  meaning no eligible evidence whatsoever, not a factor with an absent timestamp.
  Persisted evidence that cannot produce a valid `SatisfiedFactor` is refused,
  fail-closed, at the boundary where it is read.
- Config accepts ISO-8601 (`PT15M`); the wire carries RFC 9470 seconds
  (`max_age="900"`). The conversion happens once, at the rendering boundary.
- Authorization re-derives the level from the persisted proof. The stored `acr`
  is a display and index projection: never a comparison input, and never an
  authority ceiling — a proof deriving `aal2` authorizes as `aal2` even if the
  stored `acr` says otherwise.

## 3a. Subject canonicalization and the morph map

Both surfaces canonicalize a subject as `SubjectKey(provider, id)` where `provider` is
`$principal->getMorphClass()` — what the Sanctum issuer already does, and what Sanctum
itself writes to `tokenable_type`. The session writer must use the same call, not
`config('auth.providers.users.model')`: those agree only while no morph map is registered,
and under one they are different providers for the same user, so session evidence would
never bind to a token.

**The morph map is part of the identity contract, and must be stable.** It determines the
provider half of every subject key Vouch persists. A host that registers, renames or removes
a map entry after sessions or tokens exist has changed what the stored provider means:

- While a map is active, the model's raw FQCN is a FOREIGN subject and is refused.
- Records written before the map was registered therefore stop binding, and their holders
  re-authenticate — the same fail-closed rule §6.5 point 4 applies to pre-existing tokens.
  Adopting them instead would assert that a subject nobody can now resolve is this user.
- The stored provider is never rewritten, so removing the map restores the old records. The
  record is intact; only its interpretation moved.

Treat a morph-map change like an app-key rotation: plan it, and expect every live session
and human token to need re-authentication. Vouch does not migrate subject keys across a map
change, because there is no way to distinguish "this alias replaced that class" from "this
alias now names a different model" without the host saying so.

## 3b. Token lifecycle causes are coarser than session causes, and why

Session refusals carry a precise operational cause — revoked, recovery-grace, legacy,
malformed, subject mismatch. Token refusals cannot, and the reason is Sanctum's design
rather than an oversight in Vouch. Measured against the shipped driver:

| token state | what reaches the token adapter |
| --- | --- |
| live | `ResolvedToken(usable: true)` |
| expired | nothing — `resolveForRequest()` returns `null` |
| revoked | nothing — `resolveForRequest()` returns `null` |

`Guard::__invoke()` returns null for every rejection, collapsing not-found, expired,
wrong-provider and callback-rejected into one answer. `SanctumTokenIssuer` defers to that
guard deliberately (§2: reading the bearer header would falsely claim requests where
Sanctum selected a cookie actor), so neither state is visible to Vouch's adapter.

**Revoked is not recoverable at any layer.** Sanctum revokes by DELETING the row — there is
no `revoked_at`, no soft delete — so a revoked token is indistinguishable from one that
never existed, in the database and not merely in the API. Retaining revoked tokens would
change Sanctum's storage model and its retention surface; this is a design decision, not a
defect, and no upstream issue is warranted.

**Expired IS recoverable, and is left as future work.** `Sanctum::authenticateAccessTokensUsing()`
is a documented extension point whose callback receives `($accessToken, $isValid)`, so a
host or Vouch itself can observe "a token was found and judged invalid". Vouch does not
register it today: it is global mutable state on a third-party facade, and claiming it
would collide with any host already using it. If token-expiry diagnostics are wanted later,
that hook is the seam — not a change to the resolver.

None of this reaches the wire. RFC 6750 renders every one of these as `invalid_token`, and
§5 keeps that deliberately indistinguishable. The cost is confined to operator diagnostics.

**What the token adapter CAN distinguish, and does:** no assurance record, subject mismatch,
malformed proof, undecodable payload, machine actor, and a human record missing its recency
anchor. `AssuranceReason::TokenUnusable` is retained as a guard for third-party issuers whose
lifecycle model can report unusability — Passport, or a host driver over a table with a
`revoked_at`. No shipped issuer produces it, which is stated here so it is understood as a
seam for others rather than a live path, in the same way §3a records that `aal3` is
unsatisfiable with the shipped vocabulary.

## 3c. Retention: the token assurance record is authentication history

`auth_token_assurances` stores what a person proved and when — factor ids, credential ids,
satisfaction timestamps, and a provider-qualified subject. That is more sensitive than the
token it describes: Sanctum's own row is an id and a hash, while this one is a description
of how someone authenticated. §3b notes that retention surface is why Sanctum declines to
keep revoked tokens; Vouch must not quietly create a worse version of it.

**Sessions are already bounded.** `vouch.sessions.revocation_retention_days` (default 30)
prunes revoked sessions, and the proof added by Task 2a rides along on that policy.

**Token assurances are NOT, and this is an obligation on Task 5.** `VouchPruneCommand` does
not touch the table, and records are orphaned silently: Sanctum ships `sanctum:prune-expired`
for hosts to schedule, and `$user->tokens()->delete()` is the ordinary revoke-all. Both hard
-delete rows without telling Vouch, so a record outlives its token indefinitely.

**Do NOT prune by `weakest_satisfied_at`.** It is authentication-evidence time, not token
age. A legitimately long-lived token has an old anchor, so an age-based sweep deletes records
for LIVE tokens — and because §2's gate is default-deny, those tokens then stop working with
no diagnosable cause. This is the obvious fix and it is wrong.

The sound mechanism is an orphan sweep: only the issuer knows whether a token still exists,
so `TokenIssuer` gains an existence check and the sweep reclaims records the issuer no longer
recognises. Explicit revocation is handled separately by `forget()` on the revocation path.
Both belong to Task 5, where revocation and the issuer contract are already open.

## 3d. The proof column is not the same guarantee on every engine

`assurance_proof` is a `json` column on MySQL and PostgreSQL and a `text` column on SQLite.
Those engines validate JSON on write; SQLite does not. Two consequences worth stating,
because a test written against one engine's behaviour will not hold on another:

- On MySQL and PostgreSQL the database itself guarantees the payload parses, so the
  adapter's decode guard is belt-and-braces. On SQLite it is load-bearing: a truncated write
  or a lost cast really can leave bytes that are not JSON.
- A test that injects malformed bytes is therefore **unreachable** on MySQL and PostgreSQL —
  the UPDATE is rejected before the read path runs. Injecting valid JSON of the wrong SHAPE
  (a scalar rather than an envelope) exercises the same refusal on all three.

This was found by the matrix rather than by review: the truncated-bytes injection passed on
SQLite and failed PostgreSQL with a 22P02 on the write, not the read.

## 4. Schema and migration

The existing table is keyed by unique `token_id`; the new key is `(issuer_key, token_key)`.

**The upgrade path is to drop and recreate.** Within Vouch that is safe:
`auth_token_assurances` has no runtime authorization consumer — it is a model and fixture
surface only — and §6.5 point 4 already forbids adopting pre-existing tokens, which are
reissued rather than backfilled because backfilling asserts a fact nobody witnessed.

That safety claim is scoped to **Vouch-owned consumers**, and deliberately no wider. Vouch
cannot establish that an installed host has no raw SQL, reporting job or security
integration reading this table. A host that reads it directly is an incompatible migration
condition, stated in the upgrade notes rather than assumed away.

- `issuer_key` — driver-owned, immutable, `string(64)`. NOT unique on its own: an
  issuer records many tokens. Uniqueness is on the COMPOSITE `(issuer_key, token_key)`,
  and putting it on this column alone would permit exactly one record per issuer.
- `token_key` — driver-owned canonical string, `string(191)` for index compatibility.
  Sanctum renders its integer primary key as a decimal string. Drivers must produce a
  stable, comparable representation; equality is byte equality, never numeric coercion.
- `subject_key` — `provider:id`, one string column, indexed. See §6.
- `auth_token_credentials(issuer_key, token_key, credential_id)` — UNIQUE on the triple,
  not merely indexed: a duplicate mapping row makes a revocation sweep miscount and, if the
  sweep is ever made idempotent by count, hides a failure to delete. A separate non-unique
  index on `credential_id` alone serves the credential-to-tokens lookup.

## 5. The RFC 9470 wire contract

Unresolvable, expired, revoked, or unrecorded:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token"
Cache-Control: no-store
Vary: Authorization, Cookie
```

Recorded, insufficient level or recency:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication", error_description="A higher assurance level is required", acr_values="vouch:aal2", max_age="900"
Cache-Control: no-store
Vary: Authorization, Cookie
```

**One physical header line, ordinary spaces after commas.** Any wrapped rendering — here,
or in parent spec §6.3 — is illustrative only; emitting it as continuation lines would be
obsolete header folding (RFC 7230 §3.2.4). Every parameter value is double-quoted per
RFC 7235 §2.1, and `max_age` is a non-negative count of seconds per RFC 9470 §3.
**Both bodies are empty** — no detail travels in the body. Six cases that Task 4 MUST test
at the HTTP boundary, and which nothing tests yet: invalid, expired, revoked, unrecorded,
insufficient-level, insufficient-recency. The first four must be byte-identical.

## 6. Subject and tenant keys

One type, used identically when resolved and when persisted: `SubjectKey`, a value object
of `(provider, id)` rendered canonically as `provider:id`. `ResolvedToken.subject` and the
stored evidence subject are the same type; the design's earlier `subject_id` is retired.

A mismatch between resolved subject and stored subject is `invalid_token`, never an
assurance failure — they mean different things and only one is safe to say.

Tenant is a nullable string; `null` means global. Equality is exact, and **global does not
satisfy tenant-scoped, nor the reverse**. Evidence minted under one tenant's policy never
authorizes under another's.

## 7. Credential mapping lifecycle

- Disabling **any** credential in the persisted proof invalidates the token. The proof was
  a set; a partial set is not a weaker proof, it is a different one.
- **Every** credential in that proof is mapped, not only the ones a policy branch happened
  to need. Since §3's amendment the proof is every factor satisfied in the attempt, and
  mapping a narrower set would leave a real credential unmapped: in the measured
  `any_of: [all_of:[totp], all_of:[password, totp]]` case, disabling the password would
  then fail to revoke a token the password helped authorize.
- A password change is a credential mutation like any other — password is a row in
  `auth_credentials` — so it maps normally. §6.5 point 6's broader rule stands on top:
  a password change revokes all human tokens for that subject by default, configurable.
- Mappings are deleted **with** the assurance record, in the same transaction, and that
  transaction commits before driver revocation is attempted.

## 8. Revocation races and failure

- Concurrent issuance versus revocation is serialized by the shared credential-mutation
  protocol. Per-credential locks alone are **not sufficient**, and this is worth stating
  because it looks sufficient: the default password-change rule revokes every human token
  for a subject, while an issuance proved by passkey or TOTP locks entirely disjoint
  credential ids. The sweep and the issuance would never contend, and a new human token
  could commit immediately after the sweep finished.

  So every human issuance and every subject-wide revocation additionally takes a
  **per-subject lock**, acquired BEFORE any credential lock, with credential locks then
  taken in credential-id order. Fixed ordering across both operations is what keeps this
  deadlock-free.
- One `CredentialMutation` facade owns the transaction, the connection, the locks and the
  writes. `BoundedLockWait` bounds only the connection handed to it, so a writer could
  otherwise satisfy every sentence here while locking one connection and writing through
  Eloquent's default — which is precisely the escape that cost a day this week.
- Driver revocation failure is tolerated and retried out of band; the token is already
  unusable because its assurance record is gone.
- A missing mapping is not an error. Revocation is idempotent and converges.
- Every credential writer obtains the same locks on the same connection. The
  `CredentialMutationBoundaryTest` enumerates permitted writers — sixteen files touch
  credentials today — and fails when a new one appears.

## 9. Residual risk

Review closed every material bypass in the eight sections above. What remains is
implementation discipline, and it is named here so the plan carries it as tasks rather
than as good intentions. Four tests must genuinely exercise, not merely assert:

- a distinct transactional connection, with the outer rollback after `issue()` returns;
- malformed persisted evidence rejected at the read boundary;
- a request carrying BOTH a session cookie and a bearer header, where Sanctum selects the
  cookie actor;
- both interleavings of issuance against subject-wide revocation.

## 10. Decisions ratified, not merely implemented

These are product and security decisions. They are recorded here so they are accepted
rather than discovered.

1. **Default-deny is token-scoped, not route-scoped.** Cookie-authenticated API traffic is
   never rejected for lacking a token record.
2. **The two-response split deliberately discloses** that a presented credential is a
   recorded Vouch token, to a caller who already holds that credential. The alternative is
   collapsing both to `invalid_token`, which forfeits the RFC 9470 step-up affordance that
   §6.3 chose the mechanism for. Possession-scoped, and documented rather than denied.
3. **Vouch does not constrain Sanctum abilities.** The host authorizes abilities and
   supplies an immutable `TokenGrant`; Vouch evaluates assurance for `token_issue` only.
   Abilities are authorization, and authorization stays the host's — the same line drawn
   in Task 6.
4. **Machine tokens are an actor class, not an assurance marker.** A departure from §6.5
   point 5, accepted for compatibility: a machine token never satisfies a human AAL
   requirement.
5. **`auth_token_assurances` is no longer keyed by a cascading Sanctum token id.** The
   2.1 persistence design specifies "FK to `personal_access_tokens` with cascade delete;
   assurance level, `amr`, credential IDs, issuing session ID, `issued_at`". Every part of
   that is replaced: the key is the composite `(issuer_key, token_key)` because a bare id
   stops being unique once the issuer is pluggable; the FK and its cascade are gone because
   Vouch does not own the issuer's schema and Sanctum's table may not exist when Vouch
   migrates; and the derived `acr`/`amr`/`credential_ids` summary is replaced by the
   immutable proof plus a normalized mapping table. Declared here because the parent
   document is otherwise still authoritative and an implementer reading it would build the
   superseded shape.
6. **`vouch:audit-tokens` is not expected in host CI by default.** It reports; `--strict`
   is opt-in. An "unknown seam" is a call site or route group the static pass could not
   resolve — a dynamic method call, a variable middleware string, a route macro. `--strict`
   fails on those as well as on known-bad ones, which makes it noisy by design; that noise
   is the honest signal that static analysis cannot prove runtime routing.
