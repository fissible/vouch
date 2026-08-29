# Vouch Phase 2.4 — Token gate implementation plan

## Goal

Bind every human-issued API token to a witnessed Vouch assurance proof, require
that proof when a registered token is presented, and invalidate the proof on
credential or subject revocation. Preserve cookie-authenticated SPA traffic,
host-owned Sanctum abilities, and a separate machine-token actor class.

This plan implements the approved design and contract addendum:

- [`2026-08-28-vouch-phase-2-4-token-gate-design.md`](../specs/2026-08-28-vouch-phase-2-4-token-gate-design.md)
- [`2026-08-29-vouch-phase-2-4-contract-addendum.md`](../specs/2026-08-29-vouch-phase-2-4-contract-addendum.md)

The addendum is normative. If an implementation choice conflicts with it, stop and
amend the addendum before coding.

## Non-negotiable gates

1. `TokenIssuer::issue()` writes every persistent effect through the supplied
   connection. A real separate connection is used in the rollback contract test;
   the outer transaction rolls back after `issue()` returns.
2. Token resolution is performed by the configured driver, not by header sniffing.
   A Sanctum `TransientToken` means cookie authentication and is not claimed.
3. The token gate is token-scoped: cookie-authenticated requests pass through;
   real registered bearer tokens require an assurance record.
4. Stored derived `acr` is never an authorization input. Authorization rebuilds
   the result from deserialized selected factors and their timestamps.
5. Assurance deletion commits before driver revocation. Driver failure cannot
   resurrect a usable Vouch token, and revocation is idempotent.
6. Subject-wide revocation and issuance take the subject lock first, then
   credential locks in deterministic order, on the same connection used for all
   writes.
7. Every RFC 9470 response is tested byte-for-byte, including the one-line
   `WWW-Authenticate` header, empty body, `Cache-Control`, and `Vary`.
8. Each task lands separately and runs its baseline identity diff. A test batch
   must not be hidden inside a net-zero mutation count.

## Task 0 — Baseline and dependency boundary

Record the starting SHA, PHP/Laravel/Sanctum compatibility range, and the current
test/migration baseline. Decide and document whether Sanctum is an optional runtime
integration (`suggest` plus an adapter binding) or a required dependency. Do not
make the package boot fail merely because Sanctum is absent unless a host enables
the Sanctum issuer.

Verify the existing `auth_token_assurances` migration/model consumers before
changing the schema. The upgrade is drop-and-recreate for Vouch-owned consumers;
document raw SQL/reporting consumers as an incompatible host condition.

**Gate:** clean baseline suite; no source changes until the dependency and upgrade
assumptions are recorded.

## Task 1 — Issuer contracts, identity, and Sanctum adapter

Add immutable value objects and contracts:

- `SubjectKey(provider, id)` with one canonical `provider:id` rendering;
- `ResolvedToken(issuerKey, tokenKey, subject, usable)`;
- `TokenGrant` with host-authorized abilities and immutable tenant/actor data;
- `IssuedToken` containing plaintext only at issuance time;
- `TokenIssuer`, including `supportsTransactionalIssuance()`.

Implement the Sanctum issuer without `$user->createToken()`. It must create the
personal access token explicitly on the supplied connection, return the canonical
decimal token key, and resolve through the same Sanctum guard used by
`auth:sanctum`. It claims only a real configured `PersonalAccessToken` whose
tokenable is the effective principal; cookie `TransientToken` and no-token cases
return `null`.

Keep machine issuance separate from assurance-bound human issuance. A driver that
cannot enlist in a caller transaction is refused for human issuance rather than
downgraded.

**Tests:** driver contract tests for expiry, deletion, revocation, tokenable
identity, abilities, cookie-SPA selection, simultaneous cookie plus bearer header,
custom groups, and unsupported transactional drivers.

**Gate:** the distinct-connection outer-rollback test proves every driver-owned
write disappears, including side writes; no `auth_token_assurances` row is written
by this task yet.

## Task 2 — Evidence model, persistence, and comparator

Introduce `AssuranceEvidence` as the common immutable value consumed by both session
and token authorization. Add strict deserialization into non-nullable
`SatisfiedFactor` values; malformed persisted evidence fails closed at the read
boundary.

Generalize `AssuranceComparator` from `AuthSession` to evidence adapters while
preserving the existing session behavior. Define and test:

- selected-proof identity and deterministic factor selection;
- derived ACR versus re-derived authorization;
- `weakest_satisfied_at = MIN(satisfied_at)`;
- UTC comparison against injected `ClockInterface`;
- ISO-8601 configuration to integer RFC `max_age` rendering;
- revoked and recovery-grace sessions/tokens;
- missing or malformed evidence.

Replace the old token assurance schema with the composite issuer/token identity,
canonical subject key, tenant, actor kind, weakest timestamp, selected-proof
payload, and normalized credential mapping table. Add an explicit migration and
upgrade note for the old `token_id` shape; do not backfill pre-existing tokens.

**Gate:** round-trip and malformed-row tests pass on SQLite, MySQL, and PostgreSQL;
authorization never branches on persisted `acr` alone.

## Task 3 — Transactional issuance and public API

Add `Vouch::issueToken()` (or the approved service seam) that:

1. requires a server-resolved, non-revoked, non-expired, non-grace session;
2. binds the session subject exactly to the requested subject;
3. evaluates the closed `token_issue` intent and obtains the selected proof;
4. acquires the per-subject lock, then selected credential locks in ID order;
5. revalidates credentials;
6. calls the issuer on the same connection;
7. writes assurance and credential mappings; and
8. commits before returning plaintext.

Client Sanctum abilities never become policy input; the host constructs the
immutable grant.

**Tests:** subject substitution, revoked/grace session refusal, policy refusal,
rollback after issuer side effects, one assurance row per canonical token identity,
mapping contents, tenant/global equality, and no plaintext persistence.

**Gate:** failed issuance leaves neither token nor assurance/mapping effects; a
successful issuance can be resolved and authorized without consulting session state.

## Task 4 — Token-scoped enforcement and RFC 9470 responses

Add `RejectsUnrecordedTokens` and the `vouch.token` alias through the existing
provider group-wiring mechanism. It must not read `Authorization` directly or
assume `auth:sanctum` has already run. Registered issuers are queried in configured
order; two claims are a loud configuration error.

For a claimed usable token, require matching subject/tenant and a valid assurance
record. Render exactly:

- invalid, expired, revoked, unrecorded, or subject-mismatched: `invalid_token`;
- recorded but insufficient level/recency: `insufficient_user_authentication` with
  `acr_values` and integer `max_age`.

Both responses are one physical `WWW-Authenticate` line, empty body,
`Cache-Control: no-store`, and `Vary: Authorization, Cookie`. Preserve the existing
interactive `RequireAssurance` comparator and add non-interactive rendering without
duplicating comparison logic.

**Tests:** all six response cases, exact headers/body, cookie API pass-through,
Sanctum bearer enforcement, cookie-plus-bearer precedence, unrelated Passport/JWT
pass-through, custom group alias, and resolver collision.

**Gate:** a directly minted/unrecorded Sanctum token is rejected on every installed
Vouch token boundary, while ordinary cookie-authenticated SPA requests remain
unchanged.

## Task 5 — Credential and subject revocation protocol

Create one `CredentialMutation` facade owning connection, transaction, subject lock,
credential locks, assurance/mapping deletion, and credential writes. Route all
sixteen current credential writers through it and add a boundary architecture test
that fails when a new writer bypasses the protocol.

On credential disable/replace/revoke, delete matching assurance records and mappings
atomically. On password change, apply the configured subject-wide human-token sweep.
Commit Vouch invalidation before invoking idempotent driver revocation; tolerate and
retry driver failure out of band.

**Tests:** every writer, selected-credential invalidation, password subject sweep,
missing mapping/idempotent retry, driver failure fail-closed behavior, concurrent
issuance versus subject-wide revocation in both interleavings, and lock ordering.

**Gate:** after the assurance-delete commit, no request can authorize the token even
if driver deletion fails; no issuance can commit after a completed subject-wide
revocation without participating in the same lock protocol.

## Task 6 — Audit command and host-facing documentation

Implement `vouch:audit-tokens` as reporting by default and opt-in `--strict`.
Report direct issuance sites, enforcement coverage, and unresolved dynamic seams;
unknown route groups, middleware variables, macros, and indirect calls must be
named, not silently ignored. Allowlisted seams require rationale and owner.

Update upgrade/adoption documentation with the Sanctum dependency boundary,
drop-and-recreate warning, token-scoped default-deny behavior, machine-token actor
model, RFC response split, and the command's intentionally noisy strict mode.

**Gate:** fixture applications cover direct, indirect, dynamic, custom-group, and
allowlisted cases; default mode is non-breaking and strict mode fails on unknown
seams.

## Task 7 — Matrix verification and release record

Run the full focused and package suites on SQLite, MySQL 8, and PostgreSQL 16.
Retain literal commands, SHA, container identifiers, migration state, test counts,
assertions, skipped tests, and response/transaction artifacts. Re-run mutation
campaigns only for affected chunks and compare row identities with the committed
baseline/rulings tooling.

Document the lock-probe boundary explicitly: PostgreSQL/MySQL evidence establishes
behavior where `FOR UPDATE` emits SQL; SQLite evidence establishes only file-level
serialization and the insert-first compensation. Do not convert cross-engine
behavioral evidence into SQLite mutation-score credit.

Update `PROJECT.md`, the relevant roadmap/2.4 plan status, changelog, and release
checklist only after all gates pass. The public-package gate additionally requires
fresh-install verification, migration upgrade tests, optional-dependency behavior,
and a documented host adoption recipe.

## Completion criteria

- All four residual-risk tests from the addendum are real interleaving/read-boundary
  tests, not assertions over mocks alone.
- Human tokens cannot authorize without a committed matching assurance record.
- Assurance is re-derived from selected immutable evidence and recency is tested at
  the exact boundary.
- Credential and subject revocation are fail-closed under concurrent issuance.
- Cookie-SPA, unrelated bearer, machine-token, and host ability semantics match the
  ratified decisions.
- Three-engine suite and migration upgrade path are green.
- Audit output states its completeness boundary.
- Documentation and roadmap status agree with the shipped implementation.
