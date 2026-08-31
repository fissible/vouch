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
   the result from the deserialized persisted factors and their timestamps.
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

## Task 2a — Persist session assurance evidence (prerequisite) — DONE (d09aefd)

**Completed 2026-08-29.** Suite 1690 passed / 1 skipped, PHPStan 0. Duet: eight
phase-1 review rounds to APPROVE, then five implementer stops on real contract
defects — every one a genuine contradiction in the frozen tests rather than an
implementer shortcut, and none of them findable by another review round.

Carried forward, agreed with the implementer and deliberately NOT done here:
`AssuranceEvidence::derivedAcr()` resolves the vocabulary through `app()`, so a
readonly value object depends on ambient container state and the same evidence
can derive different levels. Fixing it means moving vocabulary resolution to the
adapter boundary across every caller and any host shipping a custom
`AssuranceVocabulary` — a cross-cutting change that belongs in its own task, not
smuggled into this one.

**Why this exists, and why it is not folded into Task 2.** The addendum's central
claim is that `acr` is a projection and authorization reads the immutable persisted
evidence. That is currently false for sessions and nothing in Task 2 made it true:
`SessionLifecycle` writes only `amr` and `acr`, and `assurance_facts` is a column
with no writer anywhere in `src/`. Leaving sessions on cached `acr` would put two
assurance models behind one comparator — the exact drift "one policy, two
renderings" exists to prevent — so this lands BEFORE token evidence rather than
inside it.

- Define the durable session proof schema and value format.
- Update `SessionLifecycle` at the login-success boundary to persist the proof — every
  factor satisfied in the successful attempt, per addendum §3 as amended — and its
  timestamps.
- Make session authorization deserialize and validate that proof.
- Reject malformed or timezone-less evidence before comparison, so PHP's default
  timezone can never become an authorization input.
- Replace the boolean comparison with a typed result distinguishing **sufficient**,
  **insufficient level**, **insufficient recency**, and **invalid or malformed
  evidence**. Task 4 renders RFC 9470 from that result rather than reconstructing
  the distinction from a boolean.

**Legacy sessions carry no proof, and are not adopted.** A session established
before this task has `acr` but no persisted evidence, and re-deriving one would
assert a fact nobody witnessed — the same rule §6.5 point 4 already applies to
pre-existing tokens. Such a session therefore satisfies no assurance requirement
and its holder re-authenticates. State the operational cost plainly in the upgrade
notes rather than offering a shortcut: on deploy, every live session loses its
assurance standing.

**Tests:** migration and upgrade, including a legacy session with no proof; real
constraint tests asserting persisted values rather than column existence — non-null
proof timestamps, canonical string factor keys, and a stored offset that survives a
round trip through a non-UTC default timezone; a genuine login-flow round trip from
success through `SessionLifecycle` to the adapter to the comparator.

The equivalent constraint tests for token identity and duplicate rejection stay in
Task 2, where the mapping table they constrain first exists.

**The four existing call sites move, or nothing changes.** `RequireAssurance`,
`RequireAbilityAssurance`, `AssuranceGateHook` and `CredentialSelfService` all
call `AssuranceComparator::isSufficient()`, which reads `AuthSession::$acr`. A new
evidence model built beside them would satisfy every new test and leave live
authorization exactly as it was. `isSufficient()` is therefore removed rather than
deprecated; the level vocabulary it also carries (`ORDER`, `isKnown()`,
`strength()`) stays put, because 2.3d's `AssuranceRequirements` depends on it and
that dependency is unrelated to cached-level comparison.

**Existing tests change, and that is phase-1 work.** Roughly eight suites build
sessions as bare `acr` rows and expect authorization to succeed — `Http/
RequireAssuranceTest`, `Http/OpenRedirectTest`, `Http/StepUpReturnTargetTest`, the
`Authorization/*` set, `Database/CredentialSelfServiceTest`, `Recovery/
GraceControllerTest`. Under 2a those rows prove nothing and their assertions
correctly begin to fail. The duet rule is that the implementer never edits a test,
so converting them onto a shared proven-session helper is part of the frozen
contract, committed and re-frozen before handoff — never left for phase 3 to
discover and fix.

**`aal3` turns out to be unsatisfiable, and 2a is what exposes it.**
`NistAssuranceVocabulary` caps at `aal2` deliberately — AAL3 needs hardware-binding
evidence the kernel never observes — so no real login has ever produced
`acr='aal3'`. Only hand-written test rows carry it, and several existing tests use
such a row to assert that an `aal3` route can be satisfied. Once the level is
derived from a proof rather than read from a column, those rows cannot exist and
the underlying fact becomes visible: a host configuring an `aal3` requirement has
built a route nobody can ever reach.

Two consequences, both owned by this task. The affected fixtures are resolved
during the first green run under phase-1 amendment rules — by the specifier, in
their own commit, re-frozen — rather than guessed at now against an
implementation that does not exist. And the host-facing docs must say plainly
that `aal3` is not satisfiable without a custom `AssuranceVocabulary`, because
configuring one today fails closed silently.

**Carried forward into Tasks 3 and 5, as a consequence of the §3 amendment.**
The proof is every factor satisfied in the attempt, so credential mapping and
locking must cover every credential in it — not the subset a policy branch
needed. Task 3 must prove this on the measured case: for
`any_of: [all_of:[totp], all_of:[password, totp]]` with both factors presented,
the token's mappings and locks include **password and totp**, and disabling
**either** invalidates the token. Mapping the narrower set would leave the
password unmapped, so disabling it would silently fail to revoke a token it
helped authorize.

**Subject canonicalization matches the token path**, via `getMorphClass()` — see
addendum §3a. The morph map is stable configuration: changing it after sessions
exist invalidates their evidence and re-authenticates their holders, which is
asserted rather than left to be discovered, and belongs in the upgrade notes
beside the legacy-session cost.

**Credential removal must invalidate the evidence, not just the column.**
`CredentialSelfService::downgradeWhenOnlyPasswordRemains()` writes `acr = 'aal1'`
and nothing else. Once authorization re-derives from the proof, that downgrades
nothing: the proof still names the removed credential and the session still
derives aal2, so a factor the user deleted keeps authorizing step-up routes. The
evidence has to stop counting it — by rewriting the proof without that factor, or
by refusing factors whose credential is no longer live. The contract asserts the
outcome and leaves the mechanism open. Found when the frozen contract was handed
to the implementer, which is the point of freezing it.

**Gate — strict, and deliberately blocking.** Session evidence must be written and
read correctly before token issuance or enforcement is built on it. Specifically: a
real successful login persists a proof; authorization refuses a session whose
persisted `acr` disagrees with its factors; a legacy proofless session is refused;
and the typed result reports the right case for each of the four outcomes. No later
task starts until those pass on all three engines.

## Task 2 — Evidence model, persistence, and comparator — DONE (2c57d52)

**Completed 2026-08-30.** Suite 1749 passed / 1 skipped, PHPStan 0. Duet: six
phase-1 review rounds to APPROVE, then three implementer stops — two on
contradictions I had left in the contract, one on a defect whose cause the
implementer diagnosed better than I did.

`OnePolicyTwoRenderingsTest` passes, which is the phase's central claim moving
from assertion to fact.

**Verified on SQLite only.** The empty-string CHECK constraints are per-driver
raw DDL, and MySQL commits DDL implicitly. The three-engine matrix in CI is what
settles whether `auth_token_assurances` and `auth_token_credentials` build and
behave on MySQL 8 and PostgreSQL 16 — treat a matrix failure there as expected
information rather than a surprise.

**Depends on Task 2a**, which establishes the evidence value, the strict
deserialization rule and the typed comparison result for sessions. Task 2 extends
that one model to tokens; it does not introduce a second one.

**Carried in from Task 1:** `AssuranceEvidence` must EXCLUDE token lifecycle and
provenance fields — token key, `issued_at`, `last_used_at`, session binding, and a
mutable ACR. Persist canonical subject and tenant identity losslessly, so the
comparator can distinguish invalid token identity from insufficient assurance.
Keep `weakest_satisfied_at` as authentication-evidence time, never issuance time,
and `(issuer_key, token_key)` as the canonical token identity from the outset.

**Already delivered by Task 2a, and NOT repeated here.** `AssuranceEvidence`,
its strict deserialization, `AssuranceRequirement`, the typed
`AssuranceComparison`/`AssuranceReason`, `EvidenceComparator` and
`AssuranceLevelComparator` all exist and are covered. Task 2's job is the TOKEN
ADAPTER and its storage — a second adapter onto one model, not a second model.
Re-asserting the value-level rules here would duplicate coverage and, worse,
create a place for the two surfaces to drift apart.

What Task 2 must establish that 2a could not:

- a token adapter producing the same `AssuranceEvidence` a session adapter does,
  judged by the same comparator against the same requirement;
- `(issuer_key, token_key)` composite identity, string-typed, replacing the old
  single `token_id`;
- the normalized credential mapping table, carrying EVERY credential in the
  proof (§7 as amended) so disabling any one of them invalidates the token;
- `actor_kind`, with machine tokens carrying no human factors and satisfying no
  AAL requirement;
- token refusals that the adapter can actually see, each with its own reason: no
  assurance record, subject mismatch, malformed proof, machine actor, and a human
  record missing its anchor. NOT revocation and expiry, which an earlier draft
  listed here before it was measured: Sanctum returns no `ResolvedToken` for
  either, so neither reaches the adapter. Only a third-party issuer reporting
  `usable: false` produces `TokenUnusable`. See addendum §3b.

Replace the old token assurance schema with the composite issuer/token identity,
canonical subject key, tenant, actor kind, weakest timestamp, persisted-proof
payload, and normalized credential mapping table. Add an explicit migration and
upgrade note for the old `token_id` shape; do not backfill pre-existing tokens.

**Gate:** round-trip and malformed-row tests pass on SQLite, MySQL, and PostgreSQL;
authorization never branches on persisted `acr` alone.

Schema assertions must test CONSTRAINTS, not column existence. A migration that
merely has the right column names can still lack a unique `(issuer_key, token_key)`,
store `token_key` numerically so `42` and `042` collide, omit indexes, or permit
a cross-issuer mapping read. `weakest_satisfied_at` being nullable is NOT such a
defect — an earlier draft listed it as one. A machine token has no
authentication instant, so a non-null column would force every machine record to
store a fiction. The defect is a HUMAN record without an anchor, which the
adapter refuses at the read boundary. Assert persisted values, duplicate rejection, string identity, null-tenant
persistence and issuer-scoped mappings.

## Task 3 — Transactional issuance and public API — DONE

**Completed 2026-08-30.** Suite 1778 passed / 1 skipped, PHPStan 0. Duet: five
phase-1 rounds to APPROVE (13, 6, 4, 2, 0 findings), then implementer stops on
three contract defects of mine, and a consensus review that found a real
session-revocation TOCTOU window in its own implementation.

Two obligations carried to Task 5, recorded in that section: `lockSubject()` is
not yet a durable per-subject lock, and machine-token issuance has no path.

Add `Vouch::issueToken(TokenGrant $grant, ?ConnectionInterface $connection = null)` that:

The connection parameter is what makes enlistment implementable. Without it,
"enlists in the caller's transaction" holds only for callers on the configured
default connection: Vouch would resolve its own, and an implementation ignoring
the supplied one passes every default-connection rollback test, because both
happen to use the same connection. The issuer, the assurance writer and the lock
manager must all receive that exact instance.


1. requires a session RESOLVED from live host authentication — currently
   authenticated, non-revoked, non-grace. NOT "non-expired": `auth_sessions` has
   no expiry column and none is added mid-phase, because browser-session
   lifetime belongs to the host's session driver, not to Vouch. And not a
   caller-supplied `AuthSession`: a passed model still carries the `revoked_at`
   it was loaded with, so a caller could hand over a session the database has
   since killed. The server row is re-read under the lock;
2. binds the session subject exactly to the requested subject;
3. evaluates the closed `token_issue` intent and obtains the persisted proof;
4. acquires the per-subject lock, then a lock on EVERY credential in that proof, in ID
   order — not only the ones a policy branch needed, or disabling an unmapped credential
   would silently fail to revoke the token it helped authorize;
5. revalidates credentials;
6. calls the issuer on the same connection;
7. writes assurance and credential mappings; and
8. NEVER opens or commits a transaction of its own — it enlists in the
   caller's, so a host that wraps issuance with its own writes and rolls back is
   not left holding a live token and assurance record it believes it undid.
   It therefore REQUIRES an active transaction and refuses without one.

That last clause closes a contradiction rather than adding a rule. Issuance
writes in three places; if it opens no transaction and none is active, each
write autocommits, so a failure after the issuer succeeds leaves a committed
token that nothing can undo — the exact leak the atomicity tests exist to catch,
made unfixable by the enlistment decision. The settled wording already assumed a
surrounding transaction ("the caller must not disclose it until the surrounding
transaction commits"); refusing without one makes that assumption enforceable
instead of implicit, and fails closed rather than issuing unsafely.

An earlier draft of this list said "commits before returning plaintext", which
contradicts enlistment: a synchronous call cannot both guarantee committed state
on return and leave the commit to a caller who may still roll back. Enlistment
wins, and the cost is a HOST OBLIGATION recorded here and in the API docs — the
plaintext is returned before the outer commit and must not be disclosed or used
until that commit succeeds.

**Tenant-scoped issuance is unavailable in this release.** `SessionLifecycle`
persists evidence with a null tenant, so no session can produce tenant-scoped
evidence and a tenant grant has nothing to match; issuance refuses, which is
correct and fail-closed. This is NOT the same as `aal3` being unsatisfiable: the
flow already knows the attempt's tenant and drops it before the session writer,
so the capability is a wiring gap rather than a missing vocabulary. No new column
is needed — the persisted proof already carries `tenant_id`. Tracked follow-up:
carry the attempt tenant into `AuthSuccess` and through to persisted session
evidence.

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

- unrecorded, subject-mismatched, machine-actor, malformed-proof, or an issuer
  reporting `usable: false`: `invalid_token`. NOT invalid/expired/revoked — see
  addendum §5 as amended: Sanctum returns no principal for those, so no issuer
  claims the request and it passes through to the host's auth middleware. Vouch
  gates assurance, not authentication;
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

**Two obligations carried from Task 3, both raised by the implementer at
consensus.**

`CredentialLockManager::lockSubject()` is not yet a durable per-subject lock: it
locks the first `auth_sessions` row for the user, with no stable subject
serialization row and no deterministic anchor. That is adequate for issuance,
where a session row always exists, and NOT adequate for a subject-wide sweep,
which must serialize against a subject that may have no live session at all.
Task 5 owns giving the subject a lockable anchor. Note
`canonicalCredentialIds()` is the single credential order and must be used
rather than `orderBy('id')` — the ids are opaque strings, so `'09'` and `'9'`
are different credentials and primary-key order cannot express that.

Machine-token issuance has no path. `Vouch::issueToken()` refuses machine grants
outright, and the design still calls for a separate machine path. Task 4 can
ENFORCE existing machine records but must not become the first consumer that
also creates them.

**Carries a retention obligation from Task 2 (addendum §3c).** The token assurance
record is authentication history — what a person proved, with which credentials,
when — and nothing reclaims it. Sessions are bounded by
`revocation_retention_days`; token assurances have no policy, and
`sanctum:prune-expired` and `$user->tokens()->delete()` orphan rows with no
notification. Task 5 must add an orphan sweep driven by an issuer existence
check, because only the issuer knows whether a token still exists, and must NOT
prune by `weakest_satisfied_at`: that is evidence age, not token age, so it
would delete records for live long-lived tokens and make them fail closed with
no diagnosable cause.

Add a guard test too — nothing currently catches a new table shipping without a
retention policy, which is how this one got missed.

Create one `CredentialMutation` facade owning connection, transaction, subject lock,
credential locks, assurance/mapping deletion, and credential writes. Route all
sixteen current credential writers through it and add a boundary architecture test
that fails when a new writer bypasses the protocol.

On credential disable/replace/revoke, delete matching assurance records and mappings
atomically. On password change, apply the configured subject-wide human-token sweep.
Commit Vouch invalidation before invoking idempotent driver revocation; tolerate and
retry driver failure out of band.

**Tests:** every writer, invalidation via ANY credential in the proof, password subject sweep,
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
- Assurance is re-derived from the immutable persisted evidence and recency is tested at
  the exact boundary.
- Credential and subject revocation are fail-closed under concurrent issuance.
- Cookie-SPA, unrelated bearer, machine-token, and host ability semantics match the
  ratified decisions.
- Three-engine suite and migration upgrade path are green.
- Audit output states its completeness boundary.
- Documentation and roadmap status agree with the shipped implementation.
