# Vouch 2.4 — token gate (design)

**Date:** 2026-08-28
**Status:** approved for planning
**Parent spec:** [`2026-08-11-vouch-design.md`](2026-08-11-vouch-design.md) §5.5, §6.2, §6.3, §6.5, §7.1
**Scope:** the token gate only. Audit sink drivers are split out as 2.4b.

## Why this exists

§6.2 names the vulnerability plainly: if a panel requires TOTP but an endpoint mints a
token on email and password alone, that endpoint is a complete MFA bypass. Strong policy
on one surface is worth nothing while a weak surface issues equally powerful credentials.
That bypass is live in the first consumer today — sluice calls `createToken()` directly in
two places.

Two pieces of this already exist and are unused: `auth_token_assurances` has been dead
schema since 2.1, and `AssuranceLevel::satisfiesRecency()` has had no caller since Phase 1.

## How this document was produced

Four decisions were settled with the maintainer, then the design was reviewed
adversarially over five rounds. Twenty-one findings were adopted. Four of them were holes
created by this design rather than inherited from the parent spec, and they are recorded
inline where they occur rather than quietly fixed, because each one is a mistake worth not
repeating:

- `token_id` alone as token identity — a security hole introduced by making `TokenIssuer`
  pluggable in the first place.
- Issuance unbound to a subject.
- The claim that the enrollment locking precedent transferred. It does not.
- A linearization guarantee that is false under snapshot isolation.

## Assumptions this design abandoned

Each of these was believed true early and is false. They are kept because the wrong
version is the one a reader is likely to arrive with.

- **Default-deny was never global.** A directly minted Sanctum token stays usable on any
  `auth:sanctum` route in `web`, a custom group, or outside both. The "unusable token"
  claim was wrong. Enforcement installs in BOTH `web` and `api`, plus a `vouch.token`
  alias for custom groups, and `vouch:doctor` reports coverage.
- **Bearer-header sniffing was wrong.** Sanctum's stateful guard can authenticate from a
  session cookie even when a bearer header is present, so header-keying would reject a
  legitimate cookie request; and it would wrongly claim unrelated Passport/JWT bearer APIs.
- **`token_id` alone is unsound.** Two drivers can each issue ID 42, so one token's
  assurance record would validate another. Identity is `(issuer_key, token_key)`.
- **Issuance was unbound to a subject.** Nothing stopped presenting a high-assurance
  session for A and minting a token for B.
- **The 401 split does disclose.** `insufficient_user_authentication` proves the credential
  resolved to a recorded Vouch token. Possession-scoped, therefore acceptable — but it will
  be documented as a deliberate disclosure, not claimed as none.
- **`vouch:audit-tokens` is restored.** It was dropped on the premise that runtime
  default-deny made it redundant; that premise is false (see the first bullet).

## Identity and ambiguity

Subjects and tokens are both canonically keyed, because a bare integer id is ambiguous the
moment more than one guard, model or driver exists.

- Subject key = provider/model namespace plus id. Enforcement requires the stored evidence
  subject to equal the resolved token subject; a mismatch is `invalid_token`, NEVER an
  assurance failure — the two mean different things and only one of them is safe to say.
- Token key = `(issuer_key, token_key)`, `issuer_key` unique and immutable per driver.
- If more than one resolver claims a request, Vouch fails closed. `resolveForRequest()`
  means "I authenticated the effective request principal", not "I can parse a credential
  out of this request".
- Tenant equality is enforced, not merely recorded: evidence minted under one tenant's
  policy must not satisfy another's. The global/null tenant is an explicit case, not a
  wildcard.

## Contract

`TokenIssuer`:
- `resolveForRequest(Request): ?ResolvedToken` — the DRIVER answers "did I authenticate
  this request, and under which key". Mechanism detection stays behind the seam rather
  than Vouch reaching into guard internals, which is the whole reason the seam exists.
  `ResolvedToken` is immutable: `(issuer_key, token_key, subject_id, usable)`, where
  `usable` accounts for expiry, deletion, revocation and tokenable validity — not a bare
  row lookup.
- `issue(ConnectionInterface, TokenGrant): IssuedToken` — must enlist in the supplied
  transaction, or the driver declares itself unsupported for assurance-bound human tokens.
  Rollback is tested against the CONTRACT, not the Sanctum implementation.
- `revoke(issuer_key, token_key): void` — idempotent; already-deleted is success.
- `issueMachineToken(ServiceIdentity, TokenGrant): IssuedToken` — separate path.

## Evidence

`AssuranceEvidence` is the canonical value both sessions and tokens adapt into, carrying
the SELECTED satisfying proof rather than all historical session factors: canonical subject
key, tenant, derived ACR, `weakest_satisfied_at`, and per factor — `factor_id`, `kind`,
`strength`, `credential_id`, `user_verified`, `phishing_resistant`, `is_multi_factor`,
`authenticator_id`, `satisfied_at`, at their existing types. Those are the keys actually
persisted today (verified: `factor_id`, `kind`, `strength`, `credential_id`), so the
adaptation is lossless reuse of the Kernel's model rather than new vocabulary. An earlier
draft said "factor", which would have collapsed `factor_id` and `kind` into one field.

Derived ACR is a display and index projection ONLY. Authorization re-evaluates the
immutable persisted factors; it never trusts a stored level, in either direction — a
stored level is not a floor and not a ceiling.

"Persisted factors" means every factor satisfied in the successful attempt, per the
amendment to §3 of the contract addendum. An earlier draft said "selected", meaning the
subset a policy branch used; that was measured and reversed.

Deliberately NOT in the evidence value, because they are provenance or lifecycle and using
them as comparison input launders assurance: `issued_at`, `last_used_at`, session binding,
raw session or token ids, and a bare mutable `acr`.

## Issuance invariants

Server-side session required; session subject === token subject; session not revoked, not
expired, not recovery-grace; a persisted proof satisfying `token_issue` at issuance time.
Never derived from an ambient `auth()->user()`.

`token_issue` is a closed typed intent resolved through the ordinary policy chain, taking a
server-constructed `TokenIssuanceContext`. Client-supplied Sanctum abilities never become
policy scope: the host authorizes requested abilities and supplies an immutable
`TokenGrant`; Vouch evaluates assurance only.

## Machine tokens

A separate actor class, not an AAL marker. `actor_kind = machine`, no human ACR, factors or
credential ids. A machine token NEVER satisfies an AAL requirement. Routes opt in by naming
machine actors; `human` is the default.

## Schema

- `auth_token_assurances`: keyed `(issuer_key, token_key)`; adds `weakest_satisfied_at`
  (indexed), `actor_kind`, and the persisted-proof payload. Recency is measured from the
  authentication evidence, never `issued_at`.
- `auth_token_credentials(issuer_key, token_key, credential_id)`, indexed. No JSON
  containment on a revocation path.

## Responses

- Unresolvable, expired, revoked or unrecorded → `401 error="invalid_token"`.
- Recorded, insufficient level or recency → `401 error="insufficient_user_authentication"`
  with `acr_values` and `max_age`.
- Both: `Cache-Control: no-store`, plus `Vary: Authorization, Cookie` — Cookie because the
  cookie-SPA path is explicitly supported and would otherwise be unvaried. `no-store` is
  the actual guarantee here and `Vary` is defence in depth; that ordering is stated so
  nobody later "optimises" the wrong one away.
- The invalid path performs comparable resolver and assurance lookup work where practical.
- The disclosure is documented, not denied: `insufficient_user_authentication` proves the
  credential resolved to a recorded Vouch token. It is possession-scoped, which is why it
  is acceptable.

## Revocation, and the two concurrency guarantees

**Durability boundary.** The assurance record and its mappings are deleted and COMMITTED
before the driver is asked to revoke. These are deliberately two transactions, not one: if
the driver revocation threw inside a shared transaction, the rollback would restore the
assurance record and resurrect a valid token — the precise opposite of fail-closed. Driver
revocation is idempotent and its failure is tolerated, because by then the token is already
unusable. Tested by forcing driver revocation to throw and asserting the token still fails.

**Linearization, and the snapshot that would have broken it.** The authorization point is
the assurance read; the revocation point is the assurance delete commit. A request that
read a valid record before that commit may finish; every decision after it fails.

That guarantee is false under snapshot isolation unless one more thing is specified, and
this is a contract boundary rather than an implementation preference. A request can open a
transaction, resolve the token — establishing its MVCC snapshot — and only then read
assurance. Under Postgres or InnoDB REPEATABLE READ that later read still sees the
pre-revocation row and authorizes. Resolution preceding assurance lookup makes this the
likely case, not the exotic one.

So token resolution and assurance authorization run on a fresh read-committed or
autocommit connection, or before any host transaction opens. The test is an interleaving:
establish A's snapshot, commit B's revocation, then assert A cannot authorize.

**One shared credential-mutation protocol.** An earlier draft claimed the enrollment
precedent transferred. It does not, and this is worth recording rather than quietly
fixing: `EnrollmentGuard` serializes on `(user_id, type)`, but an issuance proof spans
several factor types at once, and the credential disable/replace/revoke paths never take
that lock at all. A mutation could therefore scan before the mapping insert and miss a
token issued a moment earlier.

So issuance and credential mutation share one protocol:

- Issuance locks every credential in the persisted proof, in a deterministic order (by
  credential id, so two concurrent operations cannot deadlock), re-checks each credential
  is still valid, then inserts the assurance record and its mappings, then commits.
- Every disable, replace and revoke path takes the same locks, invalidates the credential,
  and removes matching assurance records and mappings atomically.

`BoundedLockWait` covers the whole serialized mutation rather than just a lock claim —
that part of the enrollment work does transfer, and is what keeps this bounded on every
engine.

**Every credential writer is fenced behind the protocol, and the inventory is tested.**
Sixteen files touch credentials today, including the attempt store's disable path and
credential self-service. A protocol that only issuance and one revocation path honour is
not a protocol. This repository already enforces exactly this kind of rule with boundary
arch tests — KernelBoundaryTest, ThrottleBoundaryTest, ThrottleKeyBoundaryTest,
LockoutBoundaryTest — so a CredentialMutationBoundaryTest enumerates the permitted writers
and fails when a new one appears. A future mutation path cannot bypass the protocol
silently; it has to argue with a test first.

## Auditing

`vouch:audit-tokens` reports direct issuance sites and enforcement coverage gaps. Reporting
by default, `--strict` to fail — matching `vouch:assurance-map` and `assurance_strict`,
because installing a package must not break a host's pipeline uninvited.

Its completeness boundary is part of its output, in the same spirit as the authorization
survey stating coverage per API rather than per package. Static analysis cannot prove
runtime route groups, middleware ordering, route macros, or indirect issuance, so the
report NAMES what it could not inspect and `--strict` fails on unknown seams as well as
known-bad ones. An allowlisted seam carries a rationale and an owner; a blanket exclusion
is not available.

## Build order

1. Issuer + identity + transaction contract, tested against real Sanctum: expiry,
   revocation, abilities, cookie-SPA selection, extra bearer header, custom groups.
2. `AssuranceEvidence` and the session adapter.
3. Issuance, with rollback and subject-binding tests.
4. Enforcement and response rendering.
5. Credential-change revocation.

Each step is testable without guessing the one after it.

## Open questions, named rather than hidden

- The exact shape of `TokenGrant` and how a host declares which abilities it authorizes.
- Whether `2.4b` audit events are emitted from the issuance transaction or after commit.
- Whether machine-token rotation belongs here or in a later phase.

## Departures from the parent spec

- §6.5 point 5 frames machine tokens as an assurance *marker*. This design makes them a
  separate actor class instead: a machine token never satisfies an AAL requirement, and
  routes opt in by naming machine actors.
- §6.5 point 7's `vouch:audit-tokens` was dropped and then restored during review. It ships
  as a reporting command with `--strict`, not a hard CI gate, and it reports its own
  completeness boundary.
