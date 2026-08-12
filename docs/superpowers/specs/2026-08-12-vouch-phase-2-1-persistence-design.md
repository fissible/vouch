# Phase 2.1 — Persistence Foundation: Design Specification

**Date:** 2026-08-12
**Status:** Approved design, not yet implemented
**Parent spec:** [`2026-08-11-vouch-design.md`](2026-08-11-vouch-design.md)
**Depends on:** Phase 1 (`Vouch\Kernel`), complete and merged

---

## 1. Scope

Phase 2 was decomposed into six sub-projects. This document specifies the first.

```
2.1 Persistence foundation   ← this document
2.2 Factor drivers           Factor contract + password, TOTP, email/SMS OTP,
                             recovery, passkey
2.3 Flow & HTTP surface      orchestrator, routes, ScreenSpec→JSON,
                             RequireAssurance both modes, rate limiting (§7.4)
2.4 Token gate & audit       auth_token_assurances, Vouch::issueToken,
                             default-deny, revocation, audit sink drivers
2.5 OIDC & federation        separate track, gated on the
                             facile-it/php-openid-client evaluation (§6.4)
2.6 Sluice adoption          first dogfood
```

OIDC is deliberately isolated: it is gated on an evaluation that may fail, and it
carries the §7.2 account-linking rules that are the highest-risk surface in the package.
Blocking six working drivers behind it would be bad sequencing. Rate limiting sits
inside 2.3 rather than standing alone, because it is meaningless without the flow it
protects.

**2.1 delivers:** ten migrations, ten Eloquent models, three contracts, and a
concurrency-safe attempt store. It delivers no authentication — nothing in 2.1 can log
anyone in. Its exit criterion is that the data layer exists and the attempt store is
provably safe under contention.

---

## 2. Recovery-grace — cross-cutting design

Spec §7.3 requires that a recovery code grant a *restricted recovery-grace session* that
reaches only security settings and forces enrollment of a real factor before becoming a
normal session. Phase 1 left this unrepresented: the kernel filters `FactorStrength::Recovery`
out of both satisfiability and assurance facts, so recovery-only evidence yields `aal0`.

That filtering is correct and stays. `aal0` is the honest answer to "how strongly do we
believe this is them?" The gap is that `aal0` cannot distinguish an anonymous visitor
from someone who just proved they hold a one-time secret we issued.

**Resolution: recovery-grace is a session mode, not an assurance level.** The kernel is
unchanged — Phase 1 stays closed, its public API surface stays stable, and the §8.1
extraction-stability clock keeps running. The distinction is carried by *how the session
was established*: the satisfied-factor list, the `amr` the parent spec already uses for
tokens in §6.3.

### Binding rules

1. **The `amr` is stored server-side**, in `auth_sessions`. Never a client-provided
   marker. This is why vouch keeps its own session record rather than using Laravel's
   session payload: the `cookie` session driver stores that payload client-side, and
   dictating the host application's session driver for vouch's convenience is out of
   scope.
2. **Recovery mode is mutually exclusive with normal authentication**, and a
   recovery-grace session **must not mint human API tokens**. This binds §6.5's
   default-deny gate: `Vouch::issueToken()` refuses for a grace session.
3. **Vouch owns and enforces its own enrollment and recovery-completion routes.**
   Authorization outside those routes remains the host application's, per the §2
   non-goal. Vouch exposes the grace state; it does not police host routes.
4. **On successful enrollment and verification of a real factor**, the session ID is
   rotated (§7.5 requires rotation on every assurance increase), the `amr` is
   **replaced, not appended**, and assurance facts are recomputed from the real
   evidence. Appending would leave the session permanently flagged as recovery and every
   later guard would misread it. The recovery event remains in the audit log; the
   *session* stops being a recovery session.
5. **A grace session must never become a persistent authentication artifact.** No
   remember-me cookie, no device-trust marking, nothing that survives the session's
   destruction. Otherwise the absolute cap is decorative — an attacker completes grace,
   gets remembered, and the cap has bought nothing. Persistent artifacts become
   available only after rotation, and only if policy allows.

### Expiry

`auth_sessions.recovery_grace_expires_at` is absolute, set at creation, default **15
minutes**, configurable, and **never extended by activity**. It is checked server-side
on **every vouch-owned recovery and enrollment route at request time** — enforcement is
per-request, not delegated to a scheduled job. On expiry the session is destroyed and
**the consumed recovery code is not restored**.

A scheduled sweep reaps expired rows. The sweep is housekeeping only and is never the
enforcement mechanism.

### Permitted and denied during grace

**Permitted**
- Enroll a *new* credential of real (non-recovery) strength, and verify it
- Read the existing credential list

**Denied**
- Delete or disable any credential — deepens lockout
- Add, change, or verify an identifier (email, phone) — takeover-shaped: an attacker
  adds their own address, then uses email recovery
- Change an existing password — takeover-shaped. Forgotten-password is a separate
  identifier-proof flow, not the recovery-code flow
- Regenerate recovery codes — would let an attacker lock the real owner out
- Link or unlink a federated identity — takeover and lockout respectively
- Consume a second recovery code
- Change remember-me or device-trust state, per rule 5
- Mint any API token, per rule 2

Vouch owns every operation on this list, so vouch enforces the list.

---

## 3. Schema

Ten tables. Nine come from parent spec §4; `auth_sessions` is new and is added to the
parent spec by amendment.

| Table | Scope | Notes beyond the parent spec |
|---|---|---|
| `auth_identifiers` | user | email / phone / username. `verified_at`, `is_primary`. Unique on (type, value). |
| `auth_credentials` | user, + `relying_party_id` | `type` (open string, see below), `strength`, `is_multi_factor`, `user_verified`, `phishing_resistant`, `authenticator_id`, `last_used_at`, `disabled_at`. Secret material uses the `encrypted` cast (§7.6). |
| `auth_federated_identities` | tenant, via connection | Non-null `connection_id` FK. **Unique `(connection_id, issuer, subject)` as a database constraint**, not a driver convention — parent §7.2 rule 1 is unenforceable otherwise. |
| `auth_challenges` | attempt | Hashed codes only, never plaintext. `expires_at`, attempt counter, IP/UA binding, `consumed_at`. |
| `auth_attempts` | request | The §4.3 state machine. Monotonic `version` for CAS, bound session context, hard `expires_at`. |
| **`auth_sessions`** | session | **New.** `session_id`, `user_id`, `amr` (JSON), `acr`, assurance facts, `recovery_grace_expires_at`, factor timestamps for §7.5 recency. |
| `auth_token_assurances` | token | FK to `personal_access_tokens` with cascade delete. Assurance level, `amr`, credential IDs, issuing session ID, `issued_at`. |
| `auth_policies` | tenant | Policy document, enumeration posture. |
| `auth_connections` | tenant | Email domain, OIDC discovery URL, client credentials (`encrypted` cast), claim mappings, JIT rules. |
| `auth_link_requests` | user | Pending federated-identity link awaiting proof of control. |

`auth_sessions` earns its place three times over: it satisfies rule 1 regardless of the
host's session driver; §7.5 requires invalidating *all other sessions* on credential
change, which needs an enumerable record; and §6.5's token gate must read the issuing
session's assurance at mint time.

**`auth_credentials.type` is an open string, not an enum.** Drivers register their own
type keys in 2.2. Defining the values here would couple persistence to a driver set that
does not exist yet.

Migrations are anonymous-class, auto-loaded by the service provider and publishable. The
user table and model are configurable; the FK targets whatever the host configures.

---

## 4. Contracts

Three, because three genuine seams exist. Everything else uses Eloquent models directly.

| Contract | Why it is a seam |
|---|---|
| `AttemptStore` | A Redis driver is planned as an additive alternative (§5). |
| `TenantResolver` | Station adapts it to `TenantContext`; Sluice uses `NullTenantResolver`. |
| `AuditSink` | Three drivers ship in 2.4: `activitylog`, `attest`, `null`. |

**Ordinary persistence uses Eloquent directly, tested against real databases.** No
repository indirection. The reasoning is specific to this project rather than general
Laravel taste: five controls have now been found here that passed while measuring
nothing, and in-memory fakes are that exact risk shape — a fake repository cannot
enforce a unique constraint or lose a CAS race, so tests against one would prove less
than they appear to.

---

## 5. The attempt store

**Database-backed only in 2.1.** A Redis driver remains additive behind the same
contract. One implementation means one concurrency suite, made genuinely adversarial,
rather than two that are plausibly correct.

Responsibility splits cleanly: **the kernel decides whether a transition is legal; the
store decides whether you won the race.** `TransitionRules::allows()` is already built
and mutation-tested in Phase 1, and the store never re-implements it.

```
transition(attempt, to, mutate):
  1. kernel: TransitionRules::allows(from, to)   → illegal? reject without writing
  2. hard expiry check on read                    → expired? destroy, reject
  3. bound-context check                          → different session? reject
  4. UPDATE ... SET state = ?, version = version + 1
       WHERE id = ? AND version = ?               → affected rows must be exactly 1
  5. lost the CAS? re-read and retry, or fail closed — never overwrite
```

Expiry is enforced **on read**, independent of any store-level TTL, so a stale row can
never be transitioned.

Challenge consumption and attempt advancement occur in **one transaction**, with the
challenge update itself guarded by `WHERE consumed_at IS NULL`. Two concurrent
submissions of the same one-time code therefore produce exactly one success at the
database level, not at the application's discretion.

---

## 6. Testing

Real databases throughout. No fakes for persistence.

**The normal suite runs on SQLite** — migrations, constraints, model behaviour, ordinary
reads and writes.

**The adversarial `AttemptStore` contention and constraint matrix runs against SQLite,
MySQL, and Postgres.** SQLite is necessary but not sufficient: it exercises migrations
and many constraints, but cannot prove MySQL or Postgres locking, transaction, and
concurrent-CAS behaviour. All three are supported targets, so all three are verified,
and the differences between their locking semantics are exactly what the matrix should
surface rather than route around.

This requires `services:` blocks for MySQL and Postgres in `.github/workflows/ci.yml` —
a CI change beyond what Phase 1 needed.

**Each concurrency test must be demonstrated failing against a deliberately non-CAS
implementation before it is trusted.** A concurrency test that cannot actually race
passes unconditionally while proving nothing — it would be the sixth such control found
in this project, and a convincing one, because the test's name would say "concurrent".

The matrix covers, at minimum:
- Parallel transitions from the same version: exactly one succeeds, the loser never
  overwrites.
- Parallel submissions of one challenge: exactly one consumption.
- Expiry enforced on read regardless of store state.
- Transition presented from a different bound context: refused.
- The `(connection_id, issuer, subject)` unique constraint under concurrent insert.

---

## 7. Out of scope for 2.1

Stated so they are not half-built:

- **No authentication.** Nothing in 2.1 logs anyone in. The `Factor` contract and all
  drivers are 2.2.
- **No HTTP surface.** Routes, middleware, and enforcement of the
  permitted/denied list in §2 are sub-project 2.3, which is where the vouch-owned
  routes exist.
- **No token issuance.** `auth_token_assurances` is created here; `Vouch::issueToken()`
  and the default-deny gate are 2.4.
- **No audit drivers.** The `AuditSink` contract is defined here; `activitylog`,
  `attest`, and `null` implementations are 2.4.
- **No Redis attempt store.**
- **No OIDC.** `auth_connections` and `auth_federated_identities` are created here so
  the constraints exist; everything that uses them is 2.5.

---

## 8. Decision log

| Decision | Choice | Rationale |
|---|---|---|
| Phase 2 shape | Six sub-projects, OIDC on its own track | OIDC is gated on an evaluation that may fail and carries the highest-risk linking rules; it must not block six working drivers. |
| Recovery-grace representation | Session mode via server-side `amr`; no kernel change | Assurance stays honest at `aal0`; keeps Phase 1 closed and the §8.1 extraction clock running; respects the §2 authorization non-goal. |
| Grace expiry | Absolute 15 min, never extended, checked per-request | An idle timeout lets an attacker hold the foothold indefinitely by keeping the session warm. |
| Grace persistence | No remember-me, no device trust, no artifact outliving the session | Otherwise the absolute cap is decorative. |
| Session record | New `auth_sessions` table | Satisfies server-side `amr` regardless of host session driver; also required by §7.5 multi-session invalidation and §6.5 token minting. |
| Attempt store backing | Database only; Redis additive later | One implementation whose concurrency is genuinely proven beats two that are plausibly proven. |
| Data access | Contracts at three real seams; Eloquent directly elsewhere | Fakes cannot enforce constraints or lose races — the failure shape this project has hit five times. |
| Test databases | SQLite for the normal suite; SQLite + MySQL + Postgres for the adversarial matrix | SQLite is a supported target and must be verified, but cannot prove the other engines' locking and transaction behaviour. |
