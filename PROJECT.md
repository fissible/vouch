# fissible/vouch — Project Roadmap

**Source of truth for what is built, what is next, and why.** Stateless: readable in a
fresh session with no prior context.

**Design spec:** [`docs/superpowers/specs/2026-08-11-vouch-design.md`](docs/superpowers/specs/2026-08-11-vouch-design.md)

**Status:** Design approved 2026-08-11. No code written. Phase 1 plan ready.

---

## What this is

A Laravel authentication package unifying password, OTP, MFA, and SSO behind one policy
engine, with a tamper-evident audit trail. Positioned for Laravel apps under compliance
pressure (SOC 2, HIPAA). First consumers are `fissible/sluice` and `fissible/station`.

It is an **orchestration layer** over Fortify, `laravel/passkeys`, Socialite, and
`spatie/laravel-one-time-passwords` — never a reimplementation of cryptography or
protocol handling.

---

## Dependency graph

```
Phase 1: Vouch\Kernel  (pure PHP, psr/clock only)
              │
              ▼
Phase 2: vouch Laravel  (persistence, drivers, HTTP, Sanctum gate)
              │
              ▼
Phase 3: vouch-ui       (Filament v5 + Blade/Livewire adapters)
```

Leaves first. Nothing in a later phase is started before its dependencies are stable.

---

## Phase 1 — `Vouch\Kernel`

Pure decision logic. No framework, no persistence, no HTTP. ~20–30% of the code and
~80% of the risk. Plan:
[`docs/superpowers/plans/2026-08-11-vouch-kernel.md`](docs/superpowers/plans/2026-08-11-vouch-kernel.md)

| # | Task | Effort | Deps | Issue | Status |
|---|---|---|---|---|---|
| 1 | Package scaffolding + kernel arch test | S | — | — | Not started |
| 2 | `FactorKind` / `FactorStrength` enums | XS | 1 | — | Not started |
| 3 | `SatisfiedFactor` value object | XS | 2 | — | Not started |
| 4 | Requirement tree + policy array parsing | S | 2 | — | Not started |
| 5 | `SatisfiabilityEvaluator` | M | 3, 4 | — | Not started |
| 6 | `PolicyResolver` resolution chain | S | 4 | — | Not started |
| 7 | `AssuranceLevel` derivation + recency | S | 3 | — | Not started |
| 8 | `AuthAttempt` transition rules | S | 5, 6 | — | Not started |
| 9 | `ScreenSpec` value objects | XS | 2, 4 | — | Not started |
| 10 | Enumeration posture response shaping | S | 9 | — | Not started |
| 11 | Kernel API surface snapshot | XS | 2–10 | — | Not started |

**Phase 1 exit criteria:**
- Arch test green: nothing under `Fissible\Vouch\Kernel` imports `Illuminate\*`,
  facades, global helpers, Eloquent types, driver namespaces, or global time.
- Mutation testing runs on the kernel in CI with committed floors: `composer mutate`
  makes two Pest passes over `Fissible\Vouch\Kernel`, requiring MSI >= 85 across every
  mutation and >= 95 over covered mutations. (Infection was dropped in Task 5 — it
  scores a Pest suite by looking for PHPUnit's `OK (…)` output line, which Pest never
  prints, so it reports every mutant killed and a fabricated 100% MSI.)
- Kernel public API surface captured as a committed snapshot (input to the §8.1
  extraction trigger).

---

## Phase 2 — vouch Laravel package

Not yet planned. Depends on Phase 1 interfaces being settled.

Expected shape, dependency-ordered: migrations and Eloquent models → `auth_attempts`
CAS persistence (§4.3) → factor drivers (password, TOTP, email OTP, SMS OTP, passkey,
recovery, OIDC) → policy/connection repositories → `RequireAssurance` middleware in both
response modes → Sanctum issuance gate (§6.5) → audit sinks → Artisan commands →
Sluice adoption.

**Gating item:** the `facile-it/php-openid-client` evaluation (§6.4) is a hard gate, not
a checkbox. If it fails, generic OIDC leaves v1 and enterprise SSO becomes broker-only.

---

## Phase 3 — `fissible/vouch-ui`

Not yet planned. Depends on Phase 2 and on `ScreenSpec` proving stable.

Filament v5 adapter (strategy B — replace the auth pages, §8.4) and Blade/Livewire
adapter. Inertia React/Vue deferred to v1.1.

---

## Decisions requiring action

| Item | Owner | Notes |
|---|---|---|
| GitHub repo creation | Allen | `fissible/vouch` does not exist remotely. Needs the standard wiring **plus** the per-repo `FISSIBLE_PAT` Actions secret — check `gh api repos/fissible/vouch/actions/secrets/FISSIBLE_PAT` returns 200 before blaming propagation delay. |
| PHP CI reusable workflow | Allen | The org has only `test-bash.yml`. Phase 1 Task 1 writes a repo-local `ci.yml` adapted from `fissible/attest`; promoting it to a reusable org workflow is a separate `fissible/.github` change. |
| Assurance level vocabulary | Deferred, not blocking | NIST AAL1/2/3 vs OIDC `acr` URIs vs vouch-specific. Phase 1 Task 7 makes this configuration via an injectable `AssuranceVocabulary`, shipping a NIST default — so the choice can be made when Phase 2 wires the public `acr_values` string (§6.3) without a code change. |
| Station Laravel 13 upgrade | Allen | Gates Station adoption, not vouch development. |

---

## Session handoff notes

**2026-08-11 — design session**

Completed: full design spec (915 lines, §1–§11), approved. Survived two adversarial
review rounds — seven findings (token issuance MFA bypass, passkey RP-ID binding,
duplicate-credential MFA, OIDC storage invariant, Socialite/OIDC gap, attempt
persistence, per-flow enumeration) and a follow-up on the kernel extraction trigger.
Repo initialised locally, restructured so `main` is an empty root commit and the design
work lives on `design/auth-spec`.

Next: execute Phase 1 Task 1 (scaffolding + arch test).

Open blocker: Task 7 needs the assurance-level vocabulary decision.

Not done: no GitHub remote, no issues filed (repo does not exist remotely yet), Phase 2
and 3 unplanned by design.
