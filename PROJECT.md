# fissible/vouch — Project Roadmap

**Source of truth for what is built, what is next, and why.** Stateless: readable in a
fresh session with no prior context.

**Design spec:** [`docs/superpowers/specs/2026-08-11-vouch-design.md`](docs/superpowers/specs/2026-08-11-vouch-design.md)

**Status:** Phase 1 (`Vouch\Kernel`) complete 2026-08-12. Phase 2 decomposed into six
sub-projects; **2.1 (persistence foundation) complete 2026-08-12**. Next: plan 2.2,
factor drivers.

### Current handoff — 2026-08-26

**2.3d is COMPLETE.** All seven tasks shipped: identifier verification
(`1224349`), credential recovery (`ff70efd`), first-credential enrollment
(`3d554a1`), credential self-service (`7e0e8f2`), the authorization survey with
both probes committed as tests (`62e0228`), the ability → assurance requirement
map (`618fcfa`), and the README plus composer `suggest` (`ce521b1`). Suite is
**1,476 passing / 1 skipped**; PHPStan sits at the same 6 pre-existing errors.

**Next: 2.4** (token gate & audit — `Vouch::issueToken`, default-deny,
revocation, audit sink drivers, plus `RequireAssurance` non-interactive per
RFC 9470). It is unplanned and needs its own spec → plan cycle. Two things
already point at it: the ability map is session-sourced and returns a stated
403 to a request carrying no Vouch session, which 2.4's token vocabulary
supersedes; and `AuthTokenAssurance` already exists as a 2.1 table with nothing
consuming it.

**Released as `v0.1.0` (2026-08-27), locally.** The developer preview is cut:
`release.sh`, `.cliff.toml` and `.github/workflows/release.yml` are wired in
from `fissible/.github`, `CHANGELOG.md` is generated, and the annotated signed
tag exists. `VERSION` was not bumped — an untagged 0.1.0 was already unreleased,
so the first release tags it as-is. 2.4 takes 0.2.0.

`fissible_release_advice` suggests `v1.0.0`; **do not follow it.** It reads the
untagged commits containing `feat:` and applies the post-1.0 bump table, which
has no 0.x case. 1.0.0 would assert an API stability this package has not
earned: the token gate is 2.4, UI adapters are Phase 3, and a host still cannot
complete a browser step-up without building the page itself.

**The tag is not published, because `vouch` has no git remote.** Nothing is
released to anyone until a GitHub repository exists and `git push --tags` runs;
the release workflow only fires on a pushed `v*` tag. Two consequences to settle
when that decision is made:

- The README says `composer require fissible/vouch`. That is only true once the
  package is on Packagist, which needs a public repository — or a documented
  Composer repository entry if it stays private. If vouch goes private, that
  install line is incomplete and must say so.
- A private repo needs `FISSIBLE_PAT` added as a per-repo Actions secret before
  CI can install `fissible/*` dependencies. It is not org-wide and `gh repo
  create` does not carry it over.

**One release-tooling fix landed upstream** in `fissible/.github` (`ea6e4ff`):
`release.sh` matched ANY tag when looking for the last release, so a stray
non-version tag would be read as a release, skip the first-release path, and
compute the bump against a point that was never released. vouch has exactly such
a tag (`pre-restructure`). It now matches `v[0-9]*`, the same pattern
`.cliff.toml` already used.

**What 5a's probes settled**, in
[`docs/authorization-integration-survey.md`](docs/authorization-integration-survey.md),
committed as tests under `tests/Authorization/` so a package upgrade breaks a
test rather than rotting the document:

- *Both packages' hooks register under either discovery order.* The survey's
  prediction that spatie's might never register was wrong —
  `ServiceProvider::callAfterResolving()` also fires immediately when the target
  is already resolved.
- *Bouncer's `before` hook is inert by default.* `Guard::$slot` defaults to
  `'after'`; `Bouncer::runBeforePolicies()` is the host switch that moves it.
- *spatie's hook is the live one, and it fails open at the center.* It grants
  whenever the user holds the permission — the only case an assurance
  requirement constrains.
- *A hook Vouch registers lands last*, and Vouch cannot register earlier:
  provider order comes from `installed.json`.
- *Bouncer's trait silently steals `can()`* from a model extending
  `Illuminate\Foundation\Auth\User`. `canAny()` is never overridden, so the
  bypass is per-method, not per-model.

**What 5b ships.** `config('vouch.assurance_requirements')` maps ability names
to `aal0`..`aal3`. `RequireAbilityAssurance` enforces in the **web and api**
groups by reading the ability names off the matched route's own
`can:`/`permission:`/`role_or_permission:` parameters, alias-resolved through
the router's table. Deny-only throughout. `AssuranceGateHook` is defense in
depth only. `vouch:assurance-map` reports requirements, sources, enforced
groups, and whether the host's user model still routes `can()` to the Gate;
`vouch.assurance_strict` refuses the boot on an undeclared ability, exempting
that command.

**Two fixes fell out of 5b.**

- `pushMiddlewareToGroup()` from a provider is **silently discarded** whenever
  the HTTP kernel resolves afterwards: `Kernel::__construct()` calls
  `syncMiddlewareToRouter()` and `Router::middlewareGroup()` replaces rather
  than merges. Production is safe (index.php resolves the kernel before
  providers boot), but Testbench is not, and the boot-time
  `ValidatesVouchSession` presence guard could pass while the deployed group no
  longer contained it. Both middleware now install through
  `callAfterResolving(Kernel::class)`.
- `auth_sessions.user_id` now casts to integer. 5b introduced the first
  comparison putting a database column against a host's `getAuthIdentifier()`.

**Two adoption traps now documented in the README**, both found by reading it
rather than by any test:

- Spatie ships **no middleware alias** on Laravel 11+, so a `permission:` route
  copied from documentation fails with "Target class [permission] does not
  exist" until the host registers the alias. This broke 5b's end-to-end tests
  too.
- Configuring an assurance map without `VOUCH_STEP_UP_URL` produces a **500 on
  the first refusal**, deliberately — Vouch ships no routeable step-up page and
  guessing would send browsers to a POST-only endpoint.

**Process notes worth keeping.** Every 2.3d task was built with the `duet`
skill: tests written and frozen with `shasum` first, codex implementing against
a contract it cannot edit. Two things earned their keep repeatedly.

*The review rounds are where the tests get real.* 5b took five rounds and 6-7
took nine. In both cases the first version proved the mechanism but not the
feature — 5b's enforcement tests all called classes directly, so the deployed
route could still fail open, and 6-7's doc tests were satisfiable by dropping a
keyword into a sentence. The routed tests and the block-co-occurrence
assertions exist because codex would not approve without them.

*Test defects outnumbered implementation defects, and each was committed as its
own phase-1 amendment* (`14fe75e`, `2802d76`, `5c15391`):

- `pinSession()` never pinned anything — it sent the session cookie
  unencrypted, `EncryptCookies` nulled it, and every request got a fresh
  session. A test asserting a REFUSAL still passed, because a row that is never
  found is refused anyway. **Write the passing half of every refusal test.**
- Two end-to-end Gate-hook tests asserted the hook denies while spatie held the
  permission — the exact fail-open the survey measured. The tests contradicted
  the design they defended.
- `PermissionedProbeUser` lacked `hasAnyPermission()`, so spatie's middleware
  refused before evaluating anything and every route returned a 403 that looked
  exactly like Vouch working.
- The provider's `Gate::before` closure had no coverage, and that gap held a
  real bug: it attached an unstarted session to the shared container request,
  which would have denied every mapped ability in every queued job.
- A fixture for a backslash-continued `composer require` failed on first run and
  exposed a bug in the regex it was pinning — the alternation was ordered so
  `[^\n]` swallowed the backslash. **Fixture the helpers, not just the feature.**

**Verify the implementer's reports.** Codex reported the suite green after 5b's
phase-4 fixes; it was not. It also twice reported stale test counts from a
cached view of the tree, and once returned REVISE whose only item was "the
README does not exist yet" — which is the RED precondition, not a defect. It
was right about far more than it was wrong about, and it correctly declined to
report a Pest count it could not establish when the shared SQLite file was
corrupted.

**Environment hazards, unchanged.** Never run the suite while codex is running —
concurrent runs corrupt the shared file-backed SQLite database and produce a
fake ~950-failure result (`rm -f $TMPDIR/vouch-test*.sqlite` and rerun).
Backgrounded shells inherit no usable `PATH`, so detached runs need
`/opt/homebrew/bin/php vendor/bin/pest`. Run PHPStan on new test files at phase
4 with `--memory-limit=1G`; the default 128M crashes the worker. `codex exec`
takes `-s workspace-write`; `--full-auto` is not a valid flag and the
bypass-sandbox flag is blocked.

### Mutation-reconciliation handoff — 2026-08-26

Resume from [`docs/superpowers/mutation/2026-08-22-reconciliation-ledger.md`](docs/superpowers/mutation/2026-08-22-reconciliation-ledger.md), not from the older phase summaries below. **The source tree is no longer unchanged, and the recorded corpus is therefore a partial baseline rather than a current one.** This paragraph previously stated that `src/` had not moved since `212212a`; that stopped being true once 2.3d landed. Five source commits have since arrived — `1224349`, `ff70efd`, `3d554a1`, `7e0e8f2` (Tasks 1-4) and `618fcfa` (Task 5b) — so any row touching the files they changed must be re-measured at a fresh baseline before it is ruled. Rows in files those commits did not touch remain valid evidence. Re-pin to the then-current SHA when the work resumes rather than reusing `96bbe4a`. The classifier tooling and all current chunk artifacts are committed, and every comparison must use stable row identities with `--baseline` (expression identity when a source edit shifts lines).

The corpus currently contains 526 classified rows: 446 executed-and-survived, 7 never-executed rows (all dispositioned, with no actionable gap), 23 engine-gated, 45 instrument-unroutable, and 5 separately tracked timeouts. The Notifications, root, console/jobs, Delivery, Flow, Kernel, Factors, Throttle, and cross-engine contention batches are complete. The keyed adjudication manifest now contains 173 entries; the remaining unadjudicated survivors are the review surface, not an inferred defect queue. The ledger's portable disposition vocabulary (engine-gated, engine-equivalent, redundant-cast, shadowed-by-earlier-guard, shadowed-by-caller-guard, idempotent-under-clamp, equivalent-by-duplicated-branch, and language-semantic equivalence) is evidence from the reconciliation, not an open queue by itself.

---

## What this is

A Laravel authentication package unifying password, OTP, MFA, and — by design, not yet
built — SSO behind one policy engine, with a tamper-evident audit trail. The shipped
factors are password, TOTP, email and SMS OTP, and recovery codes; federation is 2.5 and
unplanned, which is why neither the README nor the Composer description claims SSO. Positioned for Laravel apps under compliance
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
| 1 | Package scaffolding + kernel arch test | S | — | — | Complete |
| 2 | `FactorKind` / `FactorStrength` enums | XS | 1 | — | Complete |
| 3 | `SatisfiedFactor` value object | XS | 2 | — | Complete |
| 4 | Requirement tree + policy array parsing | S | 2 | — | Complete |
| 5 | `SatisfiabilityEvaluator` | M | 3, 4 | — | Complete |
| 6 | `PolicyResolver` resolution chain | S | 4 | — | Complete |
| 7 | `AssuranceLevel` derivation + recency | S | 3 | — | Complete |
| 8 | `AuthAttempt` transition rules | S | 5, 6 | — | Complete |
| 9 | `ScreenSpec` value objects | XS | 2, 4 | — | Complete |
| 10 | Enumeration posture response shaping | S | 9 | — | Complete |
| 11 | Kernel API surface snapshot | XS | 2–10 | — | Complete |

**Phase 1 exit criteria — all met:**
- Arch test green: nothing under `Fissible\Vouch\Kernel` imports `Illuminate\*`,
  facades, global helpers, Eloquent types, driver namespaces, or global time.
- Mutation testing runs on the kernel in CI with committed floors: `composer mutate`
  makes two Pest passes over `Fissible\Vouch\Kernel`. The covered-MSI floor (≥ 95) is
  the primary test-quality gate, measuring mutation survival only on lines the test
  suite actually exercises. The full-MSI floor (≥ 80) serves a narrower purpose: catching
  a class shipped with no tests at all, which the covered pass cannot detect. Full-MSI
  is systematically depressed by mutations on class constants, enum cases, and `match`
  arms that PHP evaluates at compile time; line coverage cannot attribute these, so
  Pest never executes them. This artifact does not imply weaker tests — the 80 floor
  allows headroom for these unexecutable mutants while still detecting wholly untested
  classes. (Infection was dropped in Task 5 — it scores a Pest suite by looking for
  PHPUnit's `OK (…)` output line, which Pest never prints, so it reports every mutant
  killed and a fabricated 100% MSI.) The full-MSI floor of 80 is provisional: it was
  set ahead of a final measured figure and should be re-tuned against the actual
  achieved full MSI at Phase 1 exit, rather than left to ossify as a number nobody
  can justify.

  **Enumerate the uncovered bucket at every threshold change, and record the
  enumeration.** "Uncovered" is a coverage-attribution claim, not an executability
  claim — verify it per mutant. The 85 → 80 retune extended a correct reading of 25
  compile-time-evaluated mutants to a bucket of 27 without re-checking, and the two it
  swept up were ordinary runtime statements in `AssuranceLevel::satisfiesRecency()`:
  the empty-evidence guard that forces a stale session to step up. It had no test at
  all, and inverting it to `return true` left the whole suite green. The final review
  caught it. The bucket now stands at 25, which is the enumeration the floor was
  actually argued from.
- Kernel public API surface captured as a committed snapshot (input to the §8.1
  extraction trigger): [`docs/kernel-api-surface.md`](docs/kernel-api-surface.md), 43
  entries, generated by `bin/kernel-api-surface.php` and enforced by
  `tests/Arch/ApiSurfaceTest.php`.

Final measured state: `composer test` — 131 passed, 356 assertions. `composer stan` —
level 9 clean over `src` and `tests`. `composer mutate` — 86.67% full MSI (≥ 80 floor),
97.47% covered MSI (≥ 95 floor). (Figures updated 2026-08-12 after the closing-work test
landed; see "Known issues carried into Phase 2" below for what it fixed.)

---

## Known issues carried into Phase 2

The SDD workspace for this branch (`.superpowers/sdd/2026-08-11-vouch-kernel/`) is
deleted after Phase 1 closes; these are the findings from it that still matter and have
no other durable home.

1. **Recovery-grace has no in-kernel representation.** The final fix wave added a
   `FactorStrength::Recovery` filter to `AssuranceFacts::fromFactors()`
   (`src/Kernel/Assurance/AssuranceFacts.php`), so a recovery-only factor set now
   correctly yields `aal0` instead of the `aal1` it produced before. But spec §7.3
   describes a *restricted recovery-grace session* — one that can reach only security
   settings and must force enrollment of a real factor before becoming a normal
   session — and nothing in the kernel expresses that state today. `aal0` is
   fail-closed and strictly safer than the old `aal1`, but it is not the same thing as
   recovery-grace, and Phase 2 must not conflate them. This is the most consequential
   item here; treat it as a Phase 2 design input, not a bug to retrofit into Phase 1.
2. **`AssuranceFacts::$strongest` uses `FactorStrength::Recovery` as its zero-value
   sentinel** for an empty factor set (same value used when the set contains only
   recovery evidence). It is pre-existing, currently inert, and no Phase 1 consumer
   treats `strongest` as a threshold rather than a report. It sits uncomfortably close
   to a hazard documented repeatedly on this branch: `Recovery->atLeast(Recovery)` is
   `0 >= 0 === true`, so any future code that treats `strongest` as a minimum bar
   rather than a descriptive field would accept a recovery code as if it met that bar.
   Flag for review if Phase 2 ever consumes `strongest` that way.
3. **The readonly boundary scan does not cover traits.** `tests/Arch/KernelBoundaryTest.php`
   verifies immutability via `class_exists()` + reflection, which is false for traits, so
   a trait would pass the scan silently regardless of its state. No trait exists under
   `src/Kernel` today. If Phase 2 adds one, extend the scan first — otherwise it bypasses
   the immutability requirement of spec §8.1 without any test noticing.
4. **The full-MSI floor of 80 remains provisional** and should be re-tuned against the
   final measured figure rather than left to ossify as an unjustified number. Measured
   value as of this closing work: **86.67%** full MSI (86.22% before the equal-instant
   tie-break test landed).

---

## Phase 2 — vouch Laravel package

Decomposed into six sub-projects, each with its own spec → plan → implementation cycle.
Design: [`docs/superpowers/specs/2026-08-12-vouch-phase-2-1-persistence-design.md`](docs/superpowers/specs/2026-08-12-vouch-phase-2-1-persistence-design.md)

| # | Sub-project | Status |
|---|---|---|
| 2.1 | Persistence foundation — ten tables, ten models, three contracts, CAS attempt store | **Complete** |
| 2.2 | Factor drivers — `Factor` contract + password, TOTP, email/SMS OTP, recovery | **Complete** |
| 2.2b | Passkey driver — split out, gated on evaluating `laravel/passkeys` 0.2.x | Not planned |
| 2.3 | Flow & HTTP — orchestrator, single `POST /vouch/auth`, `ScreenSpec`→JSON, session lifecycle, recovery-grace enforcement, `RequireAssurance` interactive | **Verification complete; email/SMS OTP issuance corrected in 2.3b Task 14** |
| 2.3b | Authentication throttling (§7.4) plus the corrective email/SMS OTP production-issuance hook — submitted-identifier/IP/tenant/global limits, backoff, lockout, challenge-attempt caps, challenge-issuance volume caps, posture-safe retry disclosure | **Implemented; mutation reconciliation evidence recorded** |
| 2.3c | OTP delivery economics (§7.4) — SMS country/spend/daily limits and CAPTCHA contract | **Substantially implemented; cross-engine lock ruling, 46 mutation gaps, and final exit criteria remain** |
| 2.3d | Account lifecycle (Fortify parity) — identifier verification, credential recovery, first-credential enrollment, credential self-service, ability→assurance requirements | **Complete** |
| 2.4 | Token gate & audit — `Vouch::issueToken`, default-deny, revocation, audit sink drivers, **plus `RequireAssurance` non-interactive (RFC 9470)** | Not planned |
| post-2.4 | Remember-me — device-bound persistent login, rotation, reuse/theft detection | Not planned |
| post-2.4 | Impersonation — two-principal sessions, actor-derived assurance, capability matrix, audited | Not planned; gated on 2.4's audit sink |
| 2.5 | OIDC & federation — separate track, gated on the client evaluation (§6.4) | Not planned |
| 2.6 | Sluice adoption — first dogfood | Not planned |

OIDC is isolated deliberately: it is gated on an evaluation that may fail and carries the
§7.2 account-linking rules, the highest-risk surface in the package. Blocking six working
drivers behind it would be bad sequencing.

### 2.1 — delivered

Plan: [`docs/superpowers/plans/2026-08-12-vouch-phase-2-1-persistence.md`](docs/superpowers/plans/2026-08-12-vouch-phase-2-1-persistence.md)

Ten migrations and models (`auth_identifiers`, `auth_credentials`,
`auth_connections`, `auth_federated_identities`, `auth_link_requests`, `auth_policies`,
`auth_token_assurances`, `auth_sessions`, `auth_attempts`, `auth_challenges`); three
contracts at genuine seams (`AttemptStore`, `TenantResolver`, `AuditSink`); and
`DatabaseAttemptStore` with compare-and-swap transitions and all-or-nothing
consume-and-advance.

2.1 delivers **no authentication** — nothing in it can log anyone in. Its purpose was a
data layer plus an attempt store whose concurrency is proven rather than argued.

Constraints now enforced by the database rather than by convention: unique
`(connection_id, issuer, subject)` and a non-null `connection_id` on federated
identities (§7.2 cross-tenant takeover guards); unique `(type, value)` on identifiers;
one assurance record per token; one live row per session binding.

`auth_sessions.session_binding` stores an HMAC-SHA256 of the host session ID keyed to
`APP_KEY`, never the raw bearer value. Deriving one without a key throws.

**Deviations from the plan, all recorded in commits:** PHPStan needs
`--memory-limit=1G` because Larastan loads the whole framework; Testbench sets no
`APP_KEY`, so `TestCase` sets a fixed one; models carry `@property` annotations because
Larastan cannot know Eloquent's dynamic attributes.

**First design input — recovery-grace.** Before anything else in Phase 2 is planned,
decide how spec §7.3's *restricted recovery-grace session* is represented. Phase 1 made
recovery-only evidence yield `aal0`, which is fail-closed and strictly safer than the
`aal1` it produced before — but `aal0` means "no assurance", whereas recovery-grace is a
real, usable session that may reach **only** security settings and must force enrollment
of a real factor before becoming normal. Those are different states. Letting `aal0`
stand in for recovery-grace would silently drop a security requirement the spec states
explicitly. See item 1 under "Known issues carried into Phase 2".

**Gating item:** the `facile-it/php-openid-client` evaluation (§6.4) is a hard gate, not
a checkbox. If it fails, generic OIDC leaves v1 and enterprise SSO becomes broker-only.

### 2.2 — delivered

Spec: [`docs/superpowers/specs/2026-08-12-vouch-phase-2-2-factor-drivers-design.md`](docs/superpowers/specs/2026-08-12-vouch-phase-2-2-factor-drivers-design.md)
Plan: [`docs/superpowers/plans/2026-08-12-vouch-phase-2-2-factor-drivers.md`](docs/superpowers/plans/2026-08-12-vouch-phase-2-2-factor-drivers.md)

The `Factor` contract and five drivers — password, TOTP, email OTP, SMS OTP, recovery
codes — plus four versioned amendments to 2.1 and the enrollment-serialization mechanism
that turns `maxActiveCredentials()` from a declaration into an invariant.

2.2 delivers **no HTTP surface and no flow orchestration.** Nothing here logs anyone in.

**One production dependency added: `spomky-labs/otphp ^11.5`.** Fortify and
`spatie/laravel-one-time-passwords` were both evaluated and rejected — the latter because
it ships its own table and requires a trait on the host's authenticatable model, breaking
both vouch's rule against touching the host user class and the rule that the store owns
every single-use mutation.

**Amendments to 2.1**, all shipped as follow-up migrations so the history shows the
amendment: `auth_credentials.identifier_id` (A), `auth_credentials.last_used_timestep`
(B), the variadic `AttemptStore::transition()` signature (C), and
`auth_challenges.credential_id` (D). Plus `auth_enrollment_locks`, a keyless mutex anchor.

**Load-bearing invariants, each demonstrated failing before being trusted:**

- Drivers never write single-use state. `RecoveryCodeFactor` returns a `DisableCredential`
  mutation rather than burning the code; the store applies it in the same transaction that
  advances the attempt. Making the driver burn it directly reproduced the denial of
  service live — a spent code and an unauthenticated user.
- The TOTP replay guard records the **matched timestep**, not a wall-clock time. otphp's
  `verify()` returns `bool` and hides which of three timestamps matched under a leeway, so
  the driver iterates candidate steps itself and never passes a leeway.
- A challenge records the credential it was delivered against; `verify()` reads the
  satisfied credential from that row rather than inferring it.
- `bound_ip` / `bound_user_agent` are compared before the code comparison, not merely
  stored.
- OTP re-enrollment re-enables and preserves the credential id, so
  `auth_token_assurances.credential_ids` references stay coherent.

### Cross-engine verification record — 2026-08-13

Run locally before 2.2 was marked complete. Every leg is the **full** suite, not a subset.

| Engine | Version | Result |
|---|---|---|
| MySQL | 8.4.11 (`mysql:8`) | 351 passed, 761 assertions |
| PostgreSQL | 16.14 (`postgres:16`) | 351 passed, 761 assertions |
| SQLite | 3.53.4, **file-backed** | 351 passed, 761 assertions |

PHP 8.4.24. Commands, verbatim:

```bash
VOUCH_TEST_DB=mysql DB_HOST=127.0.0.1 DB_PORT=33106 DB_DATABASE=vouch_test \
  DB_USERNAME=root DB_PASSWORD=password vendor/bin/pest

VOUCH_TEST_DB=pgsql DB_HOST=127.0.0.1 DB_PORT=54106 DB_DATABASE=vouch_test \
  DB_USERNAME=postgres DB_PASSWORD=password vendor/bin/pest

rm -f /tmp/vouch-matrix.sqlite && touch /tmp/vouch-matrix.sqlite
VOUCH_TEST_DB=sqlite VOUCH_SQLITE_PATH=/tmp/vouch-matrix.sqlite vendor/bin/pest
```

Environment variables go on as a **prefix**. `env $VAR` does not work — zsh does not
word-split unquoted variables, and that mistake cost a full matrix run twice in this
project, most recently during this very verification.

**The enrollment-lock removal probe — observed on two engines, not three.**

With `EnrollmentGuard::acquire()`'s `insertOrIgnore` and `lockForUpdate` commented out:

- **PostgreSQL — the predicted signature, measured.** Both named tests failed with
  `refusal=none`, and the recovery test's actual state was **20 active credentials across
  two generations** (`["gen-b","gen-a"]`).
- **MySQL — password test showed the predicted signature; the recovery test did not.** It
  failed with a raw `1205 Lock wait timeout` on B's insert instead. Cause: A's *zero-row*
  `UPDATE ... WHERE user_id/type` takes an InnoDB **gap lock** over that range, which
  blocks B. The plan asserted a zero-row disable "takes no row locks" — true of row locks,
  false of gap locks. So on MySQL, InnoDB gap locking does part of the serialization the
  enrollment lock is credited with.
- **SQLite — deliberately not run as protocol evidence.** A's `insertOrIgnore` takes that
  engine's database-wide write lock before B runs, so removing the guard makes B fail busy
  rather than commit a second set. That failure would evidence the engine's global writer
  serialization, not the enrollment-lock protocol.

What SQLite *does* prove, and the other two cannot: a contended enrollment there produces
a typed `EnrollmentRefusalReason::Contended` rather than a driver error, exercising
`busy_timeout`, the driver-code `5` match, and the `QueryException` → `EnrollmentRefused`
mapping. Verified passing.

**Two defects the matrix caught that no single-engine run would have:**

1. `journal_mode => wal` in `tests/TestCase.php` broke the entire file-backed SQLite
   contention suite. Laravel re-issues the pragma on every connection and switching
   journal mode needs an exclusive lock, so later connections failed with `SQLITE_BUSY`
   before any test body ran. It hid because the default database is `:memory:`, where the
   contention suite skips itself — reachable only with `VOUCH_SQLITE_PATH` set, which is
   exactly what CI does. Removed; the serialization does not need WAL.
2. The error-classification test dropped a table inside `RefreshDatabase`'s transaction.
   **MySQL implicitly commits on DDL**, so the savepoint vanished and the rollback threw
   `PDOException: SAVEPOINT trans2 does not exist` instead of the expected
   `QueryException`. Passed on SQLite and Postgres, which support transactional DDL. Moved
   to `tests/Database/EnrollmentGuardErrorsTest.php` under `DatabaseMigrations`.

### Security fixes from the final whole-branch review

Three defects that twelve scoped reviews each saw only a slice of, all fixed in `991d3a4`:

1. **An empty submitted code verified successfully.** `(int) ''` is `0`, so a set-but-empty
   `VOUCH_OTP_LENGTH=` — which deploy tooling emits routinely — made `generateCode()`
   return `''`, stored as `Hash::make('')`; and `password_verify('', hash_of(''))` is
   `true`. Recovery was contained by `FactorStrength::Recovery` being filtered out of
   satisfiability, but **OTP was not** and would have satisfied a `PossessionWeak`
   requirement. Fixed with constructor guards on `RecoveryCodeFactor` and `OtpFactor` plus
   empty-secret rejection in all five drivers — in recovery's case *after* normalisation,
   so a submission of only spaces and hyphens is caught too.
2. **Revoking an OTP credential did not invalidate its outstanding challenge.** The other
   three drivers filter `disabled_at` at verify time; `OtpFactor::verify()` read only the
   challenge row, and `GuardsChallengeTarget` hooks `creating`. A revoked credential's live
   code kept working for the rest of its TTL — a security action that silently did nothing.
3. **`challenge()` did not validate a caller-supplied credential's type**, so an
   email-specific policy was satisfiable by an SMS credential.

**A calibration point about the mutation figures.** `composer mutate` is scoped to
`--class="Fissible\Vouch\Kernel"`, and the kernel is untouched by this phase. The 86.67% /
97.47% scores are evidence that the kernel still works and say **nothing** about the five
drivers, the store amendments, or the enrollment guard — all of which sit outside the
mutation gate entirely. Widening that scope to Phase 2 code is a candidate for 2.3.

**Nine assertions that could not fail were found and fixed across this phase**, most of
them originating in the plan rather than in an implementation. The last was caught during
the final fix wave itself: `ChallengeTargetViolation extends InvalidArgumentException`, so
the obvious form of the revoked-credential test would have passed with the driver guard
deleted, because the model-layer guard throws a subclass. Treat a green suite here as weak
evidence until the control has been shown failing.

**A time-bomb test the merge verification caught.** `TotpFactorTest` froze the clock to a
fixed calendar instant (`2026-08-13 12:00:00`) and created attempts whose `expires_at` was
ten minutes later — but `AttemptStore` evaluates expiry with the database's
`CURRENT_TIMESTAMP`, not the frozen application clock. Every run after 12:10 UTC on that
date returned `Expired` instead of `Succeeded`, so three replay tests failed permanently
from that moment on. The suite was green only because every run until then happened before
the threshold. The freeze is now anchored to real `now()` aligned with `startOfMinute()`,
which keeps the two clocks in agreement while preserving the step-boundary determinism the
TOTP arithmetic needs. This is the same app-clock/database-clock seam documented on
`DatabaseAttemptStore::now()`, reaching the tests rather than production.

**Still true: `database-matrix` has never run in CI.** This record is the local
equivalent, which is not the same claim. The job now also covers `tests/Factors`.

### Carried into 2.3 and beyond

- **Passkey is 2.2b**, gated on evaluating `laravel/passkeys` 0.2.x. Until it lands,
  `isMultiFactor`, `userVerified` and `phishingResistant` are `false` on every driver and
  the kernel never emits `aal2` from a single factor.
- **Password rehash-on-verify is absent, and that is a security-maintenance limitation,
  not a deferred optimisation.** Raising the bcrypt cost reaches new and changed passwords
  only; a user who never changes theirs keeps the hash they enrolled with indefinitely.
- **Recovery verification costs up to ten hash comparisons per attempt.** Accepted;
  rate limiting is 2.3's and this driver deliberately does not invent its own.
- **`FactorFailure::BindingMismatch`** is a deliberate sixth case beyond the design spec's
  five: a wrong request context is a different fact from a wrong code, and collapsing them
  is a disclosure judgement belonging to `ErrorShaper`.
- **Enrollment is serialized, not queued.** A contended enrollment refuses with
  `Contended` after a bounded wait (`vouch.enrollment.lock_wait_seconds`, default 5). 2.3
  decides whether the HTTP surface retries or surfaces it.
- **Typed enrollment/verification DTOs** remain a follow-up; `enroll()` and `verify()`
  take arrays validated per driver at entry.

---

## Phase 3 — `fissible/vouch-ui`

Not yet planned. Depends on Phase 2 and on `ScreenSpec` proving stable.

Filament v5 adapter (strategy B — replace the auth pages, §8.4) and Blade/Livewire
adapter. Inertia React/Vue deferred to v1.1.

---

## Decisions requiring action

| Item | Owner | Notes |
|---|---|---|
| GitHub repo creation | **Deferred to Phase 2 — decided 2026-08-12** | `fissible/vouch` deliberately does not exist remotely yet. Phase 1 is a kernel with no Laravel integration, so `composer require fissible/vouch` today yields a policy engine you cannot authenticate with — publishing now invites confused issues on a package whose whole pitch is trustworthiness. Deferring also avoids doing the `FISSIBLE_PAT` dance twice. When created: standard wiring **plus** the per-repo `FISSIBLE_PAT` Actions secret — verify `gh api repos/fissible/vouch/actions/secrets/FISSIBLE_PAT` returns 200 before blaming propagation delay (a 404 means it was never added; that misdiagnosis has cost a retry cycle before). |
| Repo visibility | **Public, when created** | Not a security question. An auth package whose security depends on nobody reading it is not secure, everything it wraps is already open source, and compliance-grade positioning means SOC 2 / HIPAA buyers will want to audit it. Verified before deciding: no secrets in tracked files, none in history, no `.env`/`.pem`/`.key` ever committed, no internal paths in code. Gated on installability, not secrecy. |
| Threat-model wording pass | **Before Sluice or Station adopts** | The design spec's §7.7 residual-risk table and this file's "Known issues carried into Phase 2" are written as internal engineering notes. That is correct now and stays correct while nothing runs this. Once a real deployment exists, phrasing like *"nothing in the kernel expresses that state"* stops reading as a scope note and starts reading as an advisory pointing at a live system. Reword known gaps as deliberate scope statements — what vouch does **not** claim to do — rather than as descriptions of what is missing. Publishing the threat model is right and must continue; the change is register, not content. Trigger is first adoption, **not** repo creation. |
| PHP CI reusable workflow | Allen | The org has only `test-bash.yml`. Phase 1 Task 1 writes a repo-local `ci.yml` adapted from `fissible/attest`; promoting it to a reusable org workflow is a separate `fissible/.github` change. |
| Assurance level vocabulary | Deferred, not blocking | NIST AAL1/2/3 vs OIDC `acr` URIs vs vouch-specific. Phase 1 Task 7 makes this configuration via an injectable `AssuranceVocabulary`, shipping a NIST default — so the choice can be made when Phase 2 wires the public `acr_values` string (§6.3) without a code change. |
| Station Laravel 13 upgrade | Allen | Gates Station adoption, not vouch development. |
| **Mutation coverage beyond `Vouch\\Kernel`** | **Decided 2026-08-13 — an explicit gate for 2.3, no longer a candidate** | `composer mutate` is scoped `--class="Fissible\\Vouch\\Kernel"`. Phase 2.2 never touched the kernel, so its 86.67% / 97.47% scores are evidence about code that phase did not write — every driver, the store amendments and the enrollment guard sit outside the gate entirely. This is not a hypothetical gap: ten assertions that could not fail were found across 2.2, most of them in Phase 2 code the mutation runs never see. 2.3 must widen the scope and set a floor for `Fissible\\Vouch` outside the kernel. Expect the initial score to be lower than the kernel's and to need work; that is the point of measuring it. |
| **Grace deadlines use the database clock** | **Decided 2026-08-13 — resolution (a)** | A grace window is a security boundary; it should be nominally 15 minutes, not 15 minutes plus or minus whatever drift exists between the application and the database. `auth_sessions.recovery_grace_expires_at` is written with each engine's own clock via a single `DatabaseTime` abstraction — MySQL `DATE_ADD(... INTERVAL n SECOND)`, Postgres `CURRENT_TIMESTAMP + (n * INTERVAL '1 second')`, SQLite `datetime('now', '+n seconds')` — and an unrecognised driver throws rather than falling back to an application timestamp. Rejected the alternative (a bounded, tested skew policy) because it leaves the effective window a function of infrastructure. Phase 2.3's three-engine matrix must prove creation, active resolution, expiry and completion all use that authority. |
| **CI `database-matrix` has never executed** | **The one material verification gap** | 2.1 and 2.2 were both verified by a local three-engine run, recorded in each phase's verification record. That is the local equivalent of the matrix, which is **not** the same claim: no evidence exists that the job itself works on a runner, and it is configured but unexercised. Closing this needs the GitHub repo (see above), so it is coupled to repo creation rather than to any phase's code. Until it runs, no cross-engine claim about vouch rests on anything but a developer laptop. |

---

## Session handoff notes

**2026-08-12 — Phase 1 closing work: killable mutant test landed, findings archived**

The fix-wave re-review (`.superpowers/sdd/2026-08-11-vouch-kernel/final-fix-rereview.md`,
now deleted along with the rest of that SDD workspace) found that the surviving
`SmallerToSmallerOrEqual` mutant at `AssuranceFacts.php:69` was mislabelled equivalent by
both the final review and the fix report — `weakestSatisfiedAt` is a public readonly
property on the frozen API surface, and two equal-instant `DateTimeImmutable` values in
different timezones are observably different once rendered, so which one a tie retains is
real behavior. The re-review's killing test was added to
`tests/Kernel/Assurance/AssuranceLevelTest.php`, verified green against the real code and
red against the mutant, then the mutant was reverted. `composer test` moved 130→131
passed / 355→356 assertions; `composer mutate` moved 86.22%→86.67% full MSI and
96.97%→97.47% covered MSI. The remaining items from that re-review that still matter are
now recorded in "Known issues carried into Phase 2" above, since the SDD workspace itself
does not survive Phase 1's close.

**2026-08-12 — Phase 1 complete (Tasks 1–11)**

Completed: `Vouch\Kernel` fully built and verified on `feat/vouch-kernel`. All 11 tasks
shipped: package scaffolding + arch test (1); `FactorKind`/`FactorStrength` enums (2);
`SatisfiedFactor` value object (3); `Requirement` tree (`AllOf`/`AnyOf`/
`FactorRequirement`) + `PolicyParser`/`PolicyDocument` (4); `SatisfiabilityEvaluator` (5);
`PolicyResolver` (6); `AssuranceLevel`/`AssuranceFacts`/`AssuranceVocabulary` +
`NistAssuranceVocabulary` default (7); `AttemptState`/`TransitionRules` (8); `ScreenSpec`
family (`AuthStep`, `FactorOption`, `FieldSpec`, `RetryPolicy`) (9);
`EnumerationPosture`/`Outcome`/`ErrorShaper` (10); kernel API surface snapshot (11).

Final gate state as merged to `main`, all green: `composer test` (131 passed, 356
assertions), `composer stan` (level 9 clean over `src` and `tests`), `composer mutate`
(86.67% full MSI / 97.47% covered MSI, both above their committed floors),
`composer validate --strict` valid. `src/Kernel` depends on nothing beyond `php` and
`psr/clock`, enforced by `tests/Arch/KernelBoundaryTest.php`.

Task 11 specifics: `docs/kernel-api-surface.md` holds 152 public API entries at
symbol-presence granularity — 26 type declarations, 43 methods, 56 public properties,
and 27 enum cases, sorted. It deliberately records *what exists and is named*, not
parameter or return types: signature-level capture would churn on harmless refactors and
make the §8.1 extraction trigger unreachable in practice. Generated by
`bin/kernel-api-surface.php` and diffed
byte-for-byte by `tests/Arch/ApiSurfaceTest.php`. Both the generator and the test reuse
`Fissible\Vouch\Tests\Support\KernelFileWalker::phpFiles()` (added in Task 1) for the
`src/Kernel` traversal, rather than each re-implementing a `RecursiveIteratorIterator`
walk — the CLI script pulls it in via `autoload-dev`, which `vendor/autoload.php`
registers. The snapshot includes interface methods (e.g.
`Assurance\AssuranceVocabulary::name`) and enum methods (`cases`/`from`/`tryFrom` on
every backed enum). The marker interface `Policy\Requirement` **is** represented, via its
type-declaration entry — an earlier method-only version of the snapshot recorded zero
entries for it, meaning the interface could have been deleted outright with no diff.
Verified deterministic: two consecutive generator runs produce byte-identical output.
Verified the test actually detects drift, three ways, each introduced and reverted:
adding a public method, removing the `FactorStrength::PossessionStrong` enum case, and
renaming a `SatisfiedFactor` promoted property all fail the test.

Decision made during execution (not previously recorded): the brief's inline
`RecursiveDirectoryIterator`/`RecursiveIteratorIterator` walk in both the test and the
generator was replaced with `KernelFileWalker::phpFiles()` per direct instruction, to
avoid a third duplicate of logic Task 1 already centralised (the untyped duplicate had
previously caused PHPStan level-9 failures across three tests).

Next: Phase 2 planning (vouch Laravel package — migrations/Eloquent models, `auth_attempts`
CAS persistence, factor drivers, policy/connection repositories, `RequireAssurance`
middleware, Sanctum issuance gate, audit sinks, Artisan commands, Sluice adoption). Not
yet planned — no task table exists for Phase 2.

Open items carried forward (see "Decisions requiring action" above, unchanged by this
session): GitHub repo for `fissible/vouch` still does not exist remotely, so no issues
are filed against Phase 1 or Phase 2 tasks; the `facile-it/php-openid-client` evaluation
gating generic OIDC is still outstanding; Station's Laravel 13 upgrade still gates
Station adoption, not vouch development itself.

Plan reconciliation: **done** (commit `fe9ac9d`). `docs/superpowers/plans/2026-08-11-vouch-kernel.md`
was written before several decisions taken during execution, and two of its code blocks
would have reintroduced defects if copied — including the `(bool)` config coercion that
silently disables the secure-by-default distinctness rule. Rather than rewrite the task
bodies, which would falsify the record of what was planned, eight
`> **AMENDED DURING EXECUTION —**` callouts were inserted immediately before each
superseded block, stating what changed and why. Read the plan with those callouts as
authoritative; the code beneath them is historical.

---

## Session handoff — 2026-08-12, Phase 2.1

Completed on `feat/vouch-2-1-persistence`, ten tasks. Delivered: ten migrations and
models, three contracts, `DatabaseAttemptStore` with CAS, the `vouch:prune` sweep, and a
cross-engine CI matrix.

**What Phase 2.2 starts from.** `AuthCredential.type` is an open string by design —
2.2's drivers register their own type keys. The `Factor` contract itself (parent spec
§3.1) does not exist yet; it is 2.2's first deliverable. `AuditSink` is defined but
deliberately unbound, with a test pinning that resolving it throws; 2.4 binds the real
drivers and must update that test rather than delete it.

**Guards that are proven, not assumed.** Each was demonstrated failing against a
deliberate violation before being trusted:
- The kernel framework ban now catches a real `Illuminate` import — it had nothing to
  catch until Laravel was installed in Task 1.
- The CAS predicate: removing it fails the stale-version and rollback tests.
- All-or-nothing consume-and-advance: swallowing the challenge refusal fails both
  rollback tests.
- The contention suite fails against a non-CAS store, and **skips** rather than passes
  against in-memory SQLite, where each connection gets its own private database.
- Foreign keys are genuinely enforced here — SQLite ignores them silently unless
  enabled.
- `UNIQUE(binding, revoked_at)` was verified to accept two live rows per binding, which
  is why the shipped index is a plain `UNIQUE(binding)`.
- The sweep must never enforce grace expiry: teaching it to delete expired-grace rows
  fails its guard test.

**Cross-engine verification, 2026-08-12.** The matrix was run locally against real
engines in Docker, because CI cannot run it yet — no GitHub remote exists.

| Engine | Version | Result |
|---|---|---|
| SQLite | file-backed (`VOUCH_SQLITE_PATH`) | 59 passed, 105 assertions |
| MySQL | 8.4.11 (`mysql:8`) | 59 passed, 105 assertions |
| PostgreSQL | 16.14 (`postgres:16`) | 59 passed, 105 assertions |

Containers, on non-colliding ports so as not to disturb other local services:

```
docker run -d --name vouch-matrix-mysql -e MYSQL_ROOT_PASSWORD=password \
  -e MYSQL_DATABASE=vouch_test -p 13306:3306 mysql:8
docker run -d --name vouch-matrix-pg -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=vouch_test -p 15432:5432 postgres:16
```

Per-leg command, matching the CI job:

```
VOUCH_TEST_DB=<sqlite|mysql|pgsql> DB_HOST=127.0.0.1 DB_PORT=<13306|15432> \
DB_DATABASE=vouch_test DB_USERNAME=<root|postgres> DB_PASSWORD=password \
  vendor/bin/pest tests/Database tests/Concurrency
```

**The matrix earned its keep on its first run**, catching a defect that would have made
the package uninstallable on MySQL: the unique index on
`auth_federated_identities(connection_id, issuer, subject)` came to 3076 bytes under
utf8mb4, four over InnoDB's 3072-byte cap, so the migration failed outright. `issuer` is
now 255 rather than 512. SQLite has no key-length limit and could never have surfaced
it. Every other index was then audited against the same cap; all are clear, the next
largest being 1148 bytes.

The CAS predicate was also proven load-bearing on each engine independently, not just
SQLite: stripping it fails the racing-transition and losing-writer-rollback tests on all
three, with identical guard attribution.

**Value bounds are enforced in PHP, not by the schema.** SQLite does not enforce
VARCHAR length at all, MySQL rejects under a strict `sql_mode` but **silently truncates
without one**, and Postgres rejects. Relying on column widths alone would make every
length assertion vacuous on the suite's default engine while leaving a non-strict MySQL
host able to truncate two distinct issuers into a collision under the unique
`(connection_id, issuer, subject)` index — defeating the §7.2 cross-tenant identity
guard from the inside.

`EnforcesValueBounds` therefore hooks the model `saving` event, so every create and
update passes through it whatever calls them. A `TenantResolver` docblock alone would
not have sufficed: `AuthConnection`, `AuthPolicy`, and `AuthAttempt` can all be written
directly by code that never read it.

The v1 contract:

| Value | Bound | Reason |
|---|---|---|
| `subject` | ≤255, ASCII | OIDC Core §2 caps `sub` at 255 ASCII characters. Enforced rather than assumed: an IdP is an input boundary, not a trusted peer. |
| `issuer` | ≤255, ASCII | `iss` has **no** protocol length cap. This is a deliberate v1 support limit — refused, never truncated or normalised. |
| `tenant_id` | ≤255 | Host-supplied via `TenantResolver::currentTenantId()`, which has no length contract of its own. |
| `identifiers.value` | ≤255 | Registration input and half of a unique index; same input-boundary class. |

**If arbitrarily long but protocol-valid issuer URIs ever need supporting, redesign the
unique key around a fixed SHA-256 issuer digest plus the stored exact issuer.** Do not
silently widen the indexed column and rediscover the InnoDB 3072-byte limit.

**Carried forward.** The ordinary recovery-code notification is specified in the 2.1
design but belongs to 2.3: verified identifiers only, post-consumption, best-effort,
auditable, and delivery failure must neither restore the consumed code nor disclose
anything to the requester.

> **Superseded 2026-08-15 — deferred to Phase 2.4.** "Auditable" needs `AuditSink`,
> which is deliberately unbound until 2.4 so audit events cannot silently vanish,
> and "best-effort" has no contract to travel on (`OtpDelivery` is OTP-shaped and
> fails closed). See `docs/superpowers/specs/2026-08-15-recovery-notification-amendment.md`.

---

## Session handoff — 2026-08-15, Task 14 (matrix rows) complete

**Blocker 1 of the Phase 2.3 mutation gate is closed.** Task 13 remains blocked,
now on blocker 2 alone (the 56 provider rows in `docs/superpowers/mutation/upstream-defect/`).
Branch `feat/vouch-2-3-flow-http` still must not merge.

Full write-up: `docs/superpowers/mutation/2026-08-15-matrix-rulings.md`.

**What the matrix actually decided.** Three of the four "matrix-required" rows were
misclassified. They were sent to the matrix on the premise that MySQL and Postgres
return numeric strings for integer columns; a direct PDO probe disproves it — on
PHP 8.4, `pdo_mysql`, `pdo_pgsql` and `pdo_sqlite` all return a native `int`. The
casts were removed and the suite re-run on both engines to confirm rather than
argue it. `AuthAttempt:42`, `AuthChallenge:39` and `AuthCredential:57` are
`equivalent`; their shared premise is now pinned by a test in `CastContractTest`
that reads through the query builder and runs on every engine, so a driver upgrade
that changes this reopens all three rulings loudly.

`AuthCredential:57` deserved the most care, since its stated risk was a replay
window. It does not exist: the authoritative guard is the SQL predicate at
`DatabaseAttemptStore.php:163-166`, evaluated engine-side against an integer
column, and the PHP fast path compares numerically in PHP 8 regardless.

**`EnrollmentGuard:97` was real, and the test gap it exposed matters more than the
row.** `acquire()` has two paths. With no lock row, `insertOrIgnore` serializes and
the second writer is refused by the insert — `lockForUpdate` is never reached. With
the row already committed, `insertOrIgnore` is a no-op and on Postgres takes no lock
at all, so `lockForUpdate` is the only thing serializing. Nothing ever deletes from
`auth_enrollment_locks`, so **every enrollment after a subject's first takes the
second path** — and all four existing contention tests took the first. The new test
`it('serializes a re-enrollment, where the lock row already exists')` seeds the row
committed and races; verified two-sided, it fails on Postgres without the call.
MySQL survives it because InnoDB takes a shared lock on the conflicting index record
during `INSERT IGNORE`. `EnrollmentGuard`'s docblock claimed both engines depend on
the call and has been corrected.

**One pre-existing defect fixed.** `CastContractTest` inserted the string `'tok-1'`
into `auth_token_assurances.token_id`, an `unsignedBigInteger`. SQLite accepted it;
MySQL strict mode rejected it. It landed in `56bb638` and had never run on the
matrix — it was this session's first failure, before any new work.

**Verified state.** SQLite default suite 681 passed / 9 skipped. `tests/Database
tests/Concurrency tests/Factors` 347 passed on each of file-backed SQLite, MySQL 8
and Postgres 16. PHPStan level 9 clean. No mutation run was re-executed this
session; the 2026-08-15 baseline in the gate README still stands.

**Running the matrix locally.** Docker containers, non-default host ports to avoid
a conflict with whatever already holds 5432 on this machine:

```bash
docker run -d --name vouch-mysql -e MYSQL_ROOT_PASSWORD=password \
  -e MYSQL_DATABASE=vouch_test -p 43307:3306 mysql:8
docker run -d --name vouch-pgsql -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=vouch_test -p 45433:5432 postgres:16

VOUCH_TEST_DB=mysql DB_HOST=127.0.0.1 DB_PORT=43307 DB_DATABASE=vouch_test \
  DB_USERNAME=root DB_PASSWORD=password \
  vendor/bin/pest tests/Database tests/Concurrency tests/Factors
```

Swap `pgsql` / `45433` / `postgres` for the other engine. Note that in zsh an
unquoted variable holding several `K=V` pairs does **not** word-split, so
`env $VARS pest` silently misconfigures the run — it reports mass failures with
zero assertions, which looks like a code break and is not one.

**Next.** Blocker 2 is unchanged and is now the sole gate item. Seven layers of the
plugin were verified correct without finding the cause; the upstream-defect directory holds
a reproduction that kills the mutations a full run reports as `UNTESTED`. Task 13
cannot close until that is resolved or an alternative control is explicitly accepted
in its place.

---

## Session handoff — 2026-08-15, blocker 2 root cause found

**The 56 provider rows were never survivors.** 42 were instrument artifacts and
are killed; 14 are genuine and still need rulings. Full record:
`docs/superpowers/mutation/upstream-defect/README.md`.

**Cause.** The plugin builds one `--filter` regex alternating every test that
covers the mutated lines. `VouchServiceProvider.php` is touched by 453 tests, so
the pattern is 37,818 bytes, and PCRE2 refuses it — "regular expression is too
large". PHPUnit's `NameFilterIterator:66` is `@preg_match(...) === 1`, so the
compile failure is swallowed and reads as "no test matches". The child selects
zero tests, prints `INFO No tests found.`, and exits 0; the plugin reads exit 0
as survival. A green suite and a silently-empty suite are the same exit code.

Threshold bisected: 409 alternations / 34,140 bytes compiles, 410 / 34,222 does
not. Not the JIT (identical at `pcre.jit=0`), not the capture groups (`(?:.*)`
and bare `.*` both fail), not tunable from php.ini.

**Blast radius is one file.** Replaying the plugin's filter construction over the
real full-suite coverage map, at whole-file union (the upper bound on any single
mutation's filter): 1 of 90 covered source files can overflow. Next largest is
`EnforcesValueBounds.php` at 19,263 bytes, a 1.8x margin under the ceiling. The
rest of the 1314-mutation baseline is unaffected.

**Corrected provider verdicts** (overflow bypassed): 49 killed / 14 untested /
6 uncovered, versus 7 / 56 / 6 before. Zero children reported "No tests found".

**Two things that make this cheap to work with.** The defect reproduces at file
scope — `vendor/bin/pest --mutate --path=src/VouchServiceProvider.php`, 149s,
exactly 56/6/7 — so no 814s full run is needed. And the parallel-worker branch is
ruled out: captured spawns show `processId: null` and only
`PEST_MUTATION_TESTING` / `PEST_MUTATION_FILE` in the child env, because
`CliConfiguration::fromArguments()` builds its InputDefinition solely from
options present in argv, so `hasOption('parallel')` is true only when `--parallel`
was actually passed.

**vendor/ is pristine.** The corrected numbers came from a temporary patch to
`MutationTest.php` (drop the filter above 30,000 bytes, run the whole suite with
`--bail`). It was a measurement instrument and has been reverted, verified by
diff against a pristine copy.

**Next, in order.**
1. Rule the 14 genuine survivors listed in the upstream-defect README — all in
   `VouchServiceProvider.php`. Classify the two `ConcatRemoveRight` rows by
   dataflow, not mutator family.
2. Regenerate the authoritative mutation manifest. IDs may be stable but no
   current outcome is attested by the pre-matrix run, and the provider's rows
   were measured by a broken instrument.
3. Choose and WRITE DOWN a durable control for the provider: carry the vendor
   patch deliberately, report upstream (the reportable defect is `@preg_match`
   swallowing a compile failure; the fix is chunking the filter), or accept
   whole-suite measurement for this one file. Without one, the next run on an
   unpatched plugin silently reports 56 survivors again.

---

## Session handoff — 2026-08-15, manifest regenerated; Task 13 still open

**Task 13 is NOT closed.** Both original blockers are resolved, but the
regenerated manifest fails one of its three closure checks.

**The durable control for the tool defect is in place.** A version-pinned
Composer patch (`patches/pest-plugin-mutate-3.0.5-chunk-filters.patch`) chunks
the plugin's derived filters below PCRE's compile limit and requires every chunk
to pass before recording survival, preserving the tool's causal signal.
`composer-exit-on-patch-failure` is set, the plugin is pinned at exactly 3.0.5,
CI's vendor cache key includes `patches/**`, and
`tests/Mutation/FilterChunkingTest.php` fails if the declaration is dropped.
Whole-suite-per-mutant was the diagnostic only — an unrelated flaky failure would
falsely credit a kill.

**Authoritative run, patched install:** 1314 mutations / 60 files / 60 RUN /
0 kernel / 0 fatals / 0 "No tests found" / 899s / 80.14%. 239 untested,
22 uncovered, 4 timeout, 1049 tested. Enumerated in
`docs/superpowers/mutation/2026-08-15-survivor-manifest.md`.

**Closure checks.**
1. Provider rows report Tested — **PASS.** 0 untested, down from 62 surviving
   rows; the 6 remaining are line 246's message, uncovered and ruled prose.
2. Only already-resolved/dispositioned classes remain — **NOT CONFIRMED.**
3. No unruled IDs introduced — **PASS.** One row looked new at ID level
   (`EnrollmentGuard` 97 -> 111) purely because a docblock correction added a net
   14 lines and IDs are position sensitive; both lines hold the identical
   statement. Verified position-independently: no file gained survivors and every
   surviving (file, mutator) pair existed in the prior manifest.

**What check 2 needs: 63 of 261 rows joined to a ruling.** A row is discharged
only by a document that rules its file-set exhaustively ("N of N ruled") —
198 rows are. The rest sit in files no such document covers:

- `Support/DatabaseTime.php` (15) — no candidate document at all, the largest gap
- `Http/Middleware/RequireAssurance.php` (6), `Vouch.php` (6), `Flow/AuthFlow.php` (5),
  `Factors/FactorRegistry.php` (4), `Http/AssuranceComparator.php` (4),
  `Attempts/DatabaseAttemptStore.php` (2), `Recovery/GraceGuard.php` (2) — no candidate
- the remainder are single-digit counts with a candidate in `2026-08-15-tail-rulings.md`,
  `2026-08-15-matrix-rulings.md` or `2026-08-15-cast-classification.md`, which make no
  exhaustive claim, so correspondence has to be established row by row

**Two errors worth not repeating.** Joining the manifest by "which document
mentions this file" over-credited badly — it counted `Vouch.php` as ruled by a
reconciliation record that only listed how many of its IDs had vanished. And the
gap in `Secrets` / `Notifications` / `DatabaseTime` exists because every
file-by-file pass was organised around namespaces that did not include them; 12
of those rows are now ruled in `2026-08-15-secrets-delivery-rulings.md`, applying
the same three disqualifying conditions the 46 exception rows used.

**Next.** Rule the 63. Start with `DatabaseTime` (15, no document) and the other
no-candidate files, then establish row-by-row correspondence for the tail and
matrix candidates. Then re-run the reconciliation; nothing else blocks Task 13.

---

## Session handoff — 2026-08-15, the mutation gate is met

The authoritative rerun on the current tree (719 tests, patched install) passes
all three closure checks. Task 13's mutation control is complete; merging is a
separate decision for the branch owner.

```
1314 mutations · 60 files · 60 RUN · 0 kernel · 0 fatals · 0 "No tests found"
225 untested · 21 uncovered · 4 timeout · 1064 tested · 81.28% · 834s
```

**246 rows require a ruling; all 246 are ruled**, across nine documents, 0 unruled
and 0 double-claimed. Enumerated in
`docs/superpowers/mutation/2026-08-15-survivor-manifest.md` in two views: 137
`(file, mutator, expression)` groups as the review unit, and the 246 raw rows as
the tool's evidence, so a future mutator-version change stays distinguishable
from duplicate mutations against one expression.

**What the reconciliation model requires**, and why each part is there:

- *Run integrity* — zero fatals, "N Mutations for M Files" matching distinct RUN
  lines, no kernel rows, and zero "No tests found" children.
- *Membership* — a file having an "N of N" document is necessary but NOT
  sufficient. Sharing a filename with a ruling is not being ruled by it; that
  error once credited `Vouch.php` to a reconciliation record that merely listed
  how many of its IDs had vanished. Each group is checked against its document's
  explicit ruled set.
- *No file gained survivors* — the separate safeguard that makes a shrinking set
  safe to inherit. A subset of an exhaustively ruled set is still ruled; a file
  that grew would carry rows no document ever saw.

**Rows are referenced by (file, mutator, expression).** Line numbers and mutation
IDs both drift — `EnrollmentGuard` moved 97 -> 111 under a docblock edit and its
ID changed with it, while the statement stayed identical.

**Durable controls now in place.** The `pest-plugin-mutate` filter defect is
patched via a version-pinned Composer patch with
`composer-exit-on-patch-failure`, CI's vendor cache key includes `patches/**`,
and `tests/Mutation/FilterChunkingTest.php` fails if the declaration is dropped.
Run the gate only on a patched install: without it the provider silently reports
56 phantom survivors.

**Defects this audit found and closed**, beyond the score:

- `AuthFlow:243` — a fail-open. A declined final transition fell through to
  `new Authenticated(...)`, handing the caller a full AuthSuccess for an attempt
  the store refused to advance. Now asserted as an invariant over every
  non-Succeeded outcome AND every link on the path, not just the case that found
  it.
- Five value bounds could drift by one in either direction unnoticed. Every
  "refuses over-length" test submitted 256 (or 281), which stays refused however
  far the bound is tightened. All six bounded values now assert both max accepted
  and max+1 rejected — the durable contract.
- `AuthController` never carried the submitted `action`, so recovery through the
  HTTP endpoint could break silently.
- `ContainerWiringTest` named 3 of the provider's 16 singletons while claiming
  all of them.
- `ProviderEffectTest` asserted publish sources were "non-empty and exist", which
  could not tell a path from its own parent directory.

**Standing rules earned here** are in the gate README. The sharpest: UNCOVERED is
a routing limitation, not a verdict — it was wrong in BOTH directions in this
audit, hiding four already-killed rows and one real fail-open.

**Next.** The recovery-code notification was resolved separately below: it is a
2.4 concern because its auditable, best-effort contract depends on the audit and
redacted delivery seams that phase owns.

---

## Scope decision — 2026-08-15: recovery-code notification deferred to 2.4

**Not implemented, by decision.** Full reasoning in
`docs/superpowers/specs/2026-08-15-recovery-notification-amendment.md`.

The 2.1 specification requires the notice to be **auditable** and **best-effort**.
Neither is available in 2.3:

- `AuditSink` has no binding and resolving it throws — a designed property, pinned
  by `TenancyTest`, because "a silently-bound no-op would discard security events
  while looking healthy". Its drivers wait on the §7.6 redaction pass that ships
  with them. Building the notice now means binding a no-op sink, emitting no audit
  event, swallowing the resolution error, or letting it break a recovery whose code
  is already consumed. All four break the spec.
- The only delivery contract is `OtpDelivery`, which is OTP-shaped and whose
  unconfigured driver throws by design. A best-effort notice routed through it
  turns into a hard failure on an unconfigured host, after consumption.

2.4 inherits the requirement plus a fixed hook point (after the FactorSatisfied
transition that carries the driver mutations), a new best-effort delivery contract
distinct from OtpDelivery, verified-identifiers-only audience, non-disclosure in
the response, and the instruction that the unbound-sink test is UPDATED rather than
deleted when the drivers land.

No `src/` change. Phase 2.3's recovery-notification disposition and verification
scope are closed; Task 14's verification record follows. The broader feature-
completeness claim is corrected after that record for the missing email/SMS OTP
issuance integration.

## Task 14 verification record — 2026-08-15

**Complete.** The final Phase 2.3 gate ran against real engines in isolated
containers and a file-backed SQLite database. Every leg ran the full suite.

| Engine | Version | Result |
|---|---|---|
| SQLite | 3.43.2, file-backed | 729 passed, 2,419 assertions |
| MySQL | 8.4.11 (`mysql:8`) | 729 passed, 2,419 assertions |
| PostgreSQL | 16.14 (`postgres:16`) | 729 passed, 2,419 assertions |

The cross-engine grace proof creates a capability with PHP two hours behind the
database, then resolves, expires, and completes it with PHP two hours ahead. It
passes on all three engines. Replacing the resolution predicate's database clock
with PHP time fails at the ahead-skew assertion, so the test is discriminating.

The `database-matrix` CI job now runs `vendor/bin/pest` rather than a partial
directory selection, covering flow, session, HTTP, and recovery paths alongside
the original database, concurrency, and factor tests. It has not run on GitHub:
the repository still has no remote, so this is local engine evidence rather than
a claim about a hosted runner.

The final default local gate was 720 passed / 9 skipped (the skips are the
contention tests, which correctly require file-backed SQLite or a server engine);
PHPStan level 9 was clean. `git diff --stat main -- src/Kernel` was empty, keeping
the Phase 1 kernel boundary unchanged.

That empty diff is the completed Phase 2.3 **kernel-boundary** result. Phase 2.3b
subsequently made its one declared kernel API amendment: `RetryPolicy::$retryAfter`,
shaped by `ErrorShaper` so ordinary backoff remains inside the kernel's single
disclosure authority. Task 4 updates the generated API surface and records the
amendment below; it does not retroactively change this Phase 2.3 verification record.
The feature-completeness correction below is independent of that kernel evidence.

Containers used non-default host ports to avoid local conflicts:

```bash
docker run -d --name vouch-phase23-mysql -e MYSQL_ROOT_PASSWORD=password \
  -e MYSQL_DATABASE=vouch_test -p 33106:3306 mysql:8
docker run -d --name vouch-phase23-pg -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=vouch_test -p 54106:5432 postgres:16
```

Commands used inline environment variables; in zsh an unquoted variable holding
several `K=V` pairs does not word-split, so `env $VARS pest` silently misconfigures
the run and reports mass failures with zero assertions.

### Post-certification correction — email/SMS OTP issuance is not integrated

The Phase 2.3 gate proved the implemented flow, HTTP, session, grace, and middleware
properties, but it did not prove every registered factor could complete end to end.
Nothing in `src/` calls `Factor::challenge()`: all four `AuthFlow::challenge()`-named
calls target `ScreenBuilder` and construct UI specs. `OtpFactor::challenge()` is the
only code that creates an `auth_challenges` row and invokes `OtpDelivery::deliver()`,
and its callers are tests. The default config nevertheless advertises
`challenges.require_credential => ['email_otp', 'sms_otp']`.

Email and SMS OTP therefore cannot issue, persist, or deliver a code through the
production flow. Password, TOTP, and recovery flow evidence remains valid; the broad
Phase 2.3 completeness claim does not. This is a correctness defect assigned to Phase
2.3b Task 14 alongside issuance-volume enforcement, not a retroactive claim that OTP
issuance was always out of scope.

Task 14 must introduce one `ChallengeIssuer` as the sole owner of production challenge
issuance. Its first decision is target-independent: build an issuance-attempt intent
from the canonical submitted identifier/factor/action and atomically charge 2.3b
volume before resolving a real target or decoy. Known and nonexistent identifiers,
including resend, must reach the same cap on the same request. Only then may it resolve
the server-owned target, pass the named 2.3c economics boundary for a real delivery,
and invoke the driver. The 2.3b path supplied the seam; 2.3c now implements the
authoritative delivery-economics contract at that boundary.

The transport lifecycle remains a named Task 14 design gate, but request-path
isolation is no longer an option within it. Today
`OtpFactor::challenge()` commits the challenge row, then performs synchronous network
delivery on the request path, with no queue and no transaction spanning the pair.
Calling that method inline reopens the timing channel; a provider failure leaves a
committed unusable row after consuming volume. Merely wrapping the pair in a database
transaction is not external atomicity—a send may succeed and the later commit fail.
No safe decoy can repair the synchronous gap: sending nothing is faster, while sending
something makes Vouch an attacker-driven mail/SMS amplifier.

The adopted boundary is a durable package-owned outbox created with the challenge,
with actual transport after the response. Its payload contains the exact issued code
and target/message data, encrypted at rest, and expires with the OTP's 120-second TTL;
a queue job may carry only the opaque outbox id. Retries resend that same payload and
never re-invoke the driver to mint a replacement code. Before implementation, Task 14
must still choose and document worker dispatch, challenge verifiability, permanent-
failure behavior, and resend coalescing. Authentication-volume accounting may not be
refunded or skipped based on target or provider outcome, because that would recreate
the state oracle it exists to close.

Outbox terminal behavior is not an exception path. Successful delivery clears the
encrypted payload immediately and retains only redacted `delivered` state until the
expiry sweep. A transient failure remains pending only inside the OTP deadline; a
permanent failure or an expired row clears the payload and becomes redacted
`undeliverable`. At cleanup, every expired row that was never delivered is classified
as expired-undelivered. A delayed job whose opaque id no longer resolves returns
successfully without retry—cleanup winning the race is normal. `vouch:prune` counts
expired-undelivered rows separately before deletion, emits the aggregate, and exits
with status `2` when the count is positive so a dead worker cannot look healthy. Exit
statuses are disjoint: `0` means pruning succeeded with no undelivered finding, `1`
means pruning itself failed, and `2` means pruning succeeded and found expired
undelivered work. Monitoring must alert on `2` as delivery-worker health, not report
the maintenance sweep as failed. The aggregate report exposes pending, overdue,
delivered, and undeliverable health only, never subjects or candidate lookup.

Laravel's scheduler collapses every non-zero command result into task failure, so a
host must not schedule this command directly with `->onFailure()`. The installation
note uses a scheduled callback that invokes `Artisan::call('vouch:prune')`, alerts the
delivery-health owner and returns normally for status `2`, and throws only for status
`1` or an unknown value. That wrapper preserves the three-state contract through the
last layer that consumes it.

---

## Phase 2.3b planning record — 2026-08-15

**Core throttling and delivery-lifecycle design complete; implementation in
progress.** Authority:

- Scope amendment:
  `docs/superpowers/specs/2026-08-15-vouch-phase-2-3b-scope-amendment.md`
- Dependency-ordered plan:
  `docs/superpowers/plans/2026-08-15-vouch-phase-2-3b-auth-throttling.md`

### Task 1 baseline — 2026-08-16

Runtime work starts from clean commit `10ad1f1d75aa08628ea8161715e3f9015d5017bd`
on `feat/vouch-2-3-flow-http`. Before any source change, the ordinary 128M suite
reported **720 passed / 9 skipped / 2,400 assertions**, and PHPStan level 9 reported
no errors. The named inherited-control set—lockout, strict retry, API/kernel surface,
payload, timing equalization, enrollment contention, challenge persistence/target,
prune, provider wiring, and OTP factor—ran on file-backed SQLite with **109 passed /
196 assertions / 0 skipped**.

The current full suite then passed unchanged on every supported engine:

| Engine | Resolved version | Result |
|---|---|---|
| SQLite | 3.53.4 | 729 passed / 2,419 assertions |
| MySQL | 8.4.11 | 729 passed / 2,419 assertions |
| PostgreSQL | 16.14 | 729 passed / 2,419 assertions |

The inherited Phase 2 mutation identity is the 2026-08-15 patched authoritative run:
**1,314 mutations / 60 files / 246 ruled rows / 4 documented timeouts / 81.28%**.
`docs/superpowers/mutation/2026-08-15-survivor-manifest.md` has SHA-256
`17b29cda3a96075ea6013986d2d9fc32287c10efe40073d59f9e169a99709912`; the pinned
plugin patch has SHA-256
`94fe6dca2546656dfc450675d0b0a5fcff6471ed9ed58a5ed2329d5656df7ad2`. This identity
is a starting point only. Task 17 regenerates and reconciles the manifest because
2.3b necessarily adds expressions.

### Task 2 canonical throttle subjects — 2026-08-16

`symfony/string` is now a direct production dependency across the Laravel-supported
Symfony 7.4/8 range; a `php -n` probe proves Unicode lowercase plus post-lowercase NFC
does not depend on this machine's native `intl` extension. `BindingDomain` carries
eight required throttle domains, and the existing Session/Attempt HMAC inputs remain
byte-identical. New multi-segment derivation uses explicit count/byte-length framing;
null tenant and empty tenant are different protocol values, and only `ThrottleKey`
may invoke it from package source.

Identifiers receive no provider-specific alias rewriting. IPv4 is parsed and rendered
canonically; IPv4-mapped IPv6 is treated as the underlying IPv4 subject; native IPv6
is normalized and masked to `/64`. Null IP skips both advisory dimensions, while an
invalid non-null IP fails loudly. Every derived value is a 64-character HMAC digest;
raw identifiers, tenants, and IPs are absent. APP_KEY rotation changes the keys and
therefore deliberately resets counters and lockouts.

The five destructive probes each fail their discriminating assertion: reuse the
identifier domain for recovery; remove post-lowercase NFC; remove the IPv6 `/64`
mask; flatten absent tenant to present-empty; or replace segment framing with naïve
NUL joining. Focused gate: **47 passed / 120 assertions**. Full gate: **739 passed / 9
skipped / 2,476 assertions**, PHPStan level 9 clean, Composer strict validation clean.

### Task 3 restoring bounded lock waits — 2026-08-16

`BoundedLockWait` now captures a host connection's current lock-wait setting per
invocation, applies the caller's bound only around lock acquisition, and restores the
captured value rather than an engine default. Its enrollment entry point retains the
separate configured duration; its shared-dimension entry point accepts no duration and
is fixed at one second. Nested scopes prove `H → 1 → 5 → 1 → H` exactly.

MySQL and SQLite restore explicitly on every exit. PostgreSQL uses a
transaction-local setting: normal and nested exits restore explicitly, while a real
statement failure leaves the transaction aborted (`25P02` rejects every subsequent
statement), so the primitive preserves the original query failure and rollback restores
the setting. Only that measured PostgreSQL-abort case is deferred; unrelated restore
failures remain loud. `LockContention` preserves the measured classifier exactly:
MySQL 1205, PostgreSQL 55P03, SQLite 5. Unknown engines and deadlock siblings remain
unclassified.

Enrollment now uses the primitive and no longer lowers the host application's future
lock tolerance on a reused connection. Direct tests own inside-scope readback,
restoration, caller/query exceptions, and nesting; real held-lock tests separately own
liveness, verified contention, typed refusal, and fail-closed enrollment. The focused
gate passed **55 tests** on each of file-backed SQLite, MySQL 8, and PostgreSQL 16
(92/94/94 assertions respectively), with no skips. The ordinary 128M gate reports
**748 passed / 10 skipped / 2,502 assertions**, and PHPStan level 9 is clean.

Five probes each fail: remove the setting write; remove restoration; restore a guessed
default instead of the captured prior; widen SQLite contention to include an unrelated
driver error; or bypass the primitive in `EnrollmentGuard`. The last probe waited for
the parked seven-second host timeout and violated the five-second liveness ceiling,
proving the integration rather than only the helper.

### Task 4 measured retry deadline — 2026-08-16

The declared kernel amendment is now live: `RetryPolicy` appends nullable
`retryAfter` as its third constructor parameter, preserving existing two-argument and
named calls. `lockedUntil` remains submitted-identifier lock state only;
`retryAfter` is a measured ordinary-backoff deadline. `ErrorShaper` remains the sole
disclosure authority: ordinary strict responses null attempts remaining and lock state
while preserving a measured retry deadline; friendly responses retain all permitted
fields; identifier lockouts retain their full policy under every posture. A policy
with no measured deadline still shapes to `retry: null` rather than fabricating an
empty object.

The generated kernel surface adds exactly
`Fissible\Vouch\Kernel\Screen\RetryPolicy::$retryAfter`; a second generator run is
byte-identical. Strict known/unknown shaping is identical when handed identical
measured state. The stronger proof that both real flow paths *produce* identical state
remains assigned to Task 12, where the counter exists.

Four manual probes fail independently: leak attempts remaining under strict posture,
leak lock state as ordinary backoff, drop retryAfter, or redact a real lock policy as
ordinary backoff. The focused kernel/API gate is **132 passed / 366 assertions**;
kernel mutation gates remain above their frozen floors at **86.96% overall (230
mutations)** and **97.54% covered-only (203 mutations)**. The ordinary suite reports
**753 passed / 10 skipped / 2,516 assertions**, and PHPStan level 9 is clean.

### Task 5 validated throttle configuration — 2026-08-16

`ThrottleConfiguration` is a provider-eager singleton rather than a collection of
inline defaults. The shipped environment-backed values remain uncast until validation,
so a set-but-blank value fails loudly instead of becoming zero. Missing keys have no
call-site fallback; changing or deleting `config/vouch.php` therefore changes or
breaks the contract in a test-visible way.

The adopted 900-second window, bounded identifier/recovery backoff schedule,
wait-out-able 900-second lock, 3600-second hard lock maximum, challenge attempt and
issuance caps, 86400-second retention, IPv6 `/64` and IPv4 observation thresholds,
and opt-in shared enforcement are all typed and relationally checked at boot. The
validator also couples those caps to the actual OTP/TOTP code space and TOTP drift
window: both fixed-window worst cases must stay at or below `10^-4`. Recovery may use
the common schedule but has no lock-authority configuration.

Focused configuration/provider gate: **91 passed / 250 assertions**; ordinary gate:
**803 passed / 10 skipped / 2,701 assertions**; PHPStan level 9 clean. Seven
destructive probes cover the no-argument default, backoff/lock ordering, retention
equality, guess-budget call, shared-IP validation, missing shipped key, and blank
environment value. Each fails at its discriminating assertion or at provider boot.

### Task 6 authentication throttle schema — 2026-08-16

Four tables now separate mutable scalar counters, submitted-identifier locks,
persistent IP-window serialization parents, and exact-generation tuple markers. They
store only domain labels, domain-separated HMAC digests, database-clock state, counts,
deadlines, and operational timestamps—never raw identifiers, IP addresses, tenant or
user ids, or readable debug values. Tuple uniqueness is
`(parent, window_started_at, tuple_digest)`, and its leftmost index prefix is the
distinct-subject `COUNT` path.

The focused migration/rollback gate passed **49 tests** on SQLite 3.53.4, MySQL
8.4.11, and PostgreSQL 16.14 (123/127/127 assertions). It caught a real mismatch before
the store existed: Laravel's `timestamps()` helper would have made every operational
timestamp nullable, so the migrations now declare all eight timestamps non-null and
without an engine default. Laravel 13 preserves `char(64)` length in MySQL/PostgreSQL
metadata but compiles it to unconstrained `varchar` on SQLite; the schema tests record
that portability boundary and retain Task 2's producer-side 64-byte HMAC proof rather
than asserting enforcement SQLite does not provide.

Named indexes cover scalar lookup/rollover/prune, active-lock lookup/prune, persistent
parent lookup/lock, tuple count, and marker pruning. Markers prune independently while
parents persist. Four destructive probes each fail: remove scalar uniqueness, omit the
window generation from tuple identity, remove cascade behavior, or make an operational
timestamp nullable. The ordinary gate reports **851 passed / 10 skipped / 2,810
assertions**, and PHPStan level 9 is clean.

### Task 7 typed throttle contract — 2026-08-16

Persistence now accepts `ThrottleSubject`, never a raw string. The value combines a
closed `ThrottleDimension` with one validated lowercase HMAC-SHA256 digest, and an
architecture test confines production construction to `ThrottleKey`. A dedicated
issuance binding domain was added when issuance became its own persisted state sink;
reusing the identifier HMAC under a different table label would have moved a
type-level separation rule back into caller convention.

`IdentifierThrottle` is the only result capable of carrying attempts remaining or
`lockedUntil`. `SharedThrottle` exposes only its explicit decision and measured
`retryAfter`, making IP/tenant/global/recovery lock authority structurally absent
rather than null by convention. Challenge-attempt and issuance-permission decisions
are separate enums, and the interface keeps identifier-first, advisory, recovery,
IP-tuple, reset, challenge, and issuance operations individually visible.

The recording implementation is retained for Task 12's real `AuthFlow` sequence
proof. It is not bound as a no-op before the control exists. Focused contract/key/arch
gate: **34 passed / 149 assertions**; PHPStan level 9 clean. Three destructive probes
fail: domain reuse for issuance, malformed/raw subject admission, and loss of the
backoff deadline. The ordinary gate reports **866 passed / 10 skipped / 2,900
assertions**.

### Task 8 scalar counters and identifier locks — 2026-08-16

`DatabaseAuthThrottleStore` now owns fixed-window scalar state. Counter creation,
rollover, and increment use the database clock; the count is incremented by one SQL
statement rather than a PHP read-modify-write. Identifier backoff is derived rather
than stored: defaults yield cumulative deadlines at 1/3/7/15/31 seconds for counts
5–9, then write one 900-second lock at count 10. Active backoff/lock state neither
increments nor extends, an expired lock rebases the next failure to a fresh window,
and full authentication can delete only the identifier counter and lock in the same
record order every failure writer uses.

The three-engine race exposed two opposite lock-acquisition requirements. SQLite
must make the unique insert its first statement, because `FOR UPDATE` is a bare read
and a later read-to-write upgrade cannot wait safely. MySQL must skip that duplicate
insert for a committed row, because two `INSERT IGNORE` shared record locks deadlock
when both upgrade to `FOR UPDATE`; MySQL/PostgreSQL therefore lock the existing row
directly. The contention harness opens both child connections before a barrier,
holds real parent locks, and proves neither child returns before release, so its exact
counts cannot pass by serial scheduling.

Focused gate on each of file-backed SQLite, MySQL 8, and PostgreSQL 16: **21 passed /
60 assertions**. The ordinary gate reports **879 passed / 12 skipped / 2,945
assertions**; the two additional default skips are the contention cells that require
file-backed SQLite. PHPStan level 9 is clean. Destructive probes kill the atomic
increment, exact-boundary predicate, lock threshold, lock deadline write,
no-extension return, and reset; the real matrix also killed the unconditional
duplicate-insert and SQLite read-first variants.

### Task 9 distinct-subject IP observation — 2026-08-16

IP breadth is an indexed count of unique tuple markers for one persistent parent and
exact database-clock generation. Repeated failures against one submitted identifier
contribute one; twenty distinct identifiers contribute twenty. IPv4 and IPv6 parents
remain separate even for equal digest bytes, parent rollover retains but excludes old
markers, and identifier reset cannot erase IP evidence.

Observe mode stays response-inert at the shipped 30/300 thresholds. When a host opts
into enforcement, the marker that crosses the distinct-subject threshold supplies the
measured backoff origin; `retryAfter` is that marker's database `created_at` plus the
configured seconds, capped by the fixed-window deadline. An active backoff admits no
new marker and therefore cannot extend itself. Repeating the same tuple creates no
new marker and cannot manufacture a breadth penalty.

Parent acquisition runs under the restoring one-second bound. Verified lock timeout
returns `SharedThrottle::skipped()` with no marker, lock state, or invented retry;
dropping the tuple table propagates the real query error. Focused behavior plus
held-parent gate on file-backed SQLite, MySQL 8, and PostgreSQL 16: **11 passed / 33
assertions per engine**. Ordinary gate: **888 passed / 14 skipped / 2,971 assertions**;
PHPStan level 9 clean. Task 10 retains the six-cell simultaneous matrix and the
PostgreSQL `lockForUpdate` destructive proof before flow integration is allowed.

### Task 10 three-engine IP contention matrix — 2026-08-16

The matrix crosses same/distinct tuples with absent, committed-active, and
committed-expired parents on file-backed SQLite, MySQL 8, and PostgreSQL 16. Each
child opens its own connection before the shared barrier. For committed parents a
third connection holds the parent until both child store calls have started, proving
the result cannot come from accidental serial scheduling.

This gate found a MySQL-only stale-snapshot defect: reading parent existence inside
the transaction established InnoDB's `REPEATABLE READ` snapshot before the writer
waited on `FOR UPDATE`. After the lock was acquired, the marker count still read the
old snapshot and admitted both distinct subjects. Existence hints now come from
autocommit before the transaction; the locked read and every decision remain inside.
The same correction applies to scalar counter creation, whose two creation paths
share the mechanism.

Removing only the IP parent `lockForUpdate()` fails PostgreSQL's distinct
committed-parent proof while the unique-insert absent-parent mechanism remains
independent. Verified one-second contention skips only IP state after authoritative
identifier state commits. Missing tables and malformed columns propagate rather than
being swallowed as contention. Focused gate: **10 passed / 59 assertions on each of
the three engines**.

### Task 11 posture-safe retry disclosure — 2026-08-16

Measured throttle state reaches the wire only through `ScreenBuilder` and the
kernel `ErrorShaper`. The builder consumes typed identifier/shared results: only an
identifier result can accompany `Outcome::Locked`, while shared results can carry
only `retryAfter`. Strict posture redacts attempts remaining for both ordinary
backoff and lockout but preserves the measured actionable deadline; friendly posture
may retain permitted counter state.

The JSON contract keeps `retry` present and null when nothing was measured. When a
policy exists it has the exact ordered keys `attemptsRemaining`, `lockedUntil`, and
`retryAfter`, with dates serialized in ATOM form. Destructive probes kill hardcoded
null, dropped retry deadlines, strict counter leakage, and shared backoff mapped to a
lock deadline. The shared-lock probe initially exposed only the strict shaper's
compensating redaction; the final test also asserts friendly output so the builder's
primary no-lock mapping is independently load-bearing. Focused gate: **48 passed /
114 assertions**. Ordinary gate: **893 passed / 22 skipped / 2,991 assertions**;
PHPStan level 9 clean.

### Task 12 authentication-flow integration — 2026-08-16

Throttle state is keyed by the submitted identifier stored on the attempt, never the
resolved user. Known and nonexistent identifiers execute the same ordered store
operations and receive identical strict-posture schedules. Tenant scope is persisted
at attempt creation; null client IP skips that dimension instead of collapsing into a
shared unknown bucket. Recovery bypasses identifier lock, advances its own scalar
counter, and leaves login failure state untouched.

Preflight happens before credential verification and never increments or extends an
active deadline. On failure the identifier/recovery transaction commits first, then
IP, tenant, and global observations run independently. A selective decorator over the
real database store proves that a following advisory failure propagates while the
identifier count stays committed. The original attempt to prove this by dropping a
table was rejected: MySQL DDL implicitly committed the test transaction, so the
observed missing-savepoint error said nothing about flow ordering.

Only a successfully committed final `Authenticated` transition resets identifier
state. First-factor satisfaction, recovery grace, and a lost compare-and-swap do not.
Destructive probes kill resolved-user keying, reset after one factor, and active
backoff fallthrough; transition and ordering assertions cover CAS-loss charging and
shared-first writes. Focused gate: **66 passed / 170 assertions**. The 13-test flow
integration file passes with **39 assertions** on SQLite, MySQL 8, and PostgreSQL 16;
ordinary gate: **906 passed / 22 skipped / 3,035 assertions**; PHPStan level 9 clean.

### Task 13 OTP challenge-attempt cap — 2026-08-16

Wrong OTP submissions now advance one database-owned per-challenge counter. The
fifth failed comparison atomically writes `attempts = 5` and `consumed_at`; a
correct fifth guess may still be consumed through the attempt transition, while a
sixth request cannot verify. Malformed, expired, consumed, and binding-mismatched
submissions remain distinct and do not masquerade as charged wrong guesses. This
state never writes identifier lock records.

Increment and invalidation are one conditional SQL update rather than a PHP
read-modify-write. A held-row two-process race proves two simultaneous wrong guesses
cannot collapse and proves a fifth wrong guess is mutually exclusive with the
existing atomic `ConsumeChallenge` transition. The matrix found one engine-specific
defect before commit: MySQL evaluates `UPDATE ... SET` assignments left-to-right, so
incrementing before the terminal `CASE` invalidated at four there. Evaluating the
terminal decision before incrementing makes the pre-write count authoritative on all
three engines.

Any named `AuthChallenge` is re-read from persistence before verification. A stale
pre-consumption Eloquent object can no longer produce a satisfied factor after
another request consumed or invalidated its row. Resend creates a new zero-count
challenge without resetting the previous row's evidence.

`AuthChallenge::$attempts` has therefore been re-ruled: its Eloquent integer cast
remains runtime-equivalent on the current three PDO drivers, but the old "no
consumer" premise is retired. SQL arithmetic and terminal consumption are the
security mechanisms, and raw/model integer shape is pinned so a driver change
reopens the cast ruling loudly. Focused gate: **9 passed / 67 assertions** on each
of file-backed SQLite, MySQL 8, and PostgreSQL 16. Ordinary gate: **913 passed /
24 skipped / 3,091 assertions**; PHPStan level 9 clean.

### Task 14 delivery-lifecycle gate — 2026-08-16

The pre-implementation gate is closed. Vouch requires a non-inline Laravel queue,
commits one encrypted TTL-bound outbox row with its challenge, dispatches only the
opaque row id after commit, and recovers the commit-before-push gap through scheduled
pending-row redispatch. Challenge verification begins at commit; provider acceptance
clears ciphertext and records delivery, permanent failure records redacted
undeliverable state, and transient failure retries the same code only until the
database deadline. Missing or swept rows are successful no-ops.

Explicit resend is charged as a new issuance event but coalesces a still-pending
challenge onto the same code. The lifecycle is deliberately at-least-once: duplicate
delivery of that same code is possible, regeneration for one outbox row is not.
Unconfigured transport or a synchronous/discarding queue fails target-independently
before charge.

Factor choice on identify is carried before user resolution. Exactly one active
credential becomes the server-owned target; zero or an ambiguous set takes a durable
decoy path and contacts no provider. The package never chooses the first target,
sends to all, or exposes a database id. The implemented 2.3c economics boundary sits
after authentication-volume permission and resolution but before the factor call;
it performs authoritative reservation and CAPTCHA escalation.

The critical chain joins the restoring database lock-wait primitive with the
auth-specific store prerequisites, then continues through the distinct-subject IP
parent/marker protocol → six-cell three-engine race matrix → flow integration →
production challenge issuance/outbox → expiry cleanup → final mutation and engine
reconciliation. Binding
domains/canonicalization, the declared
`RetryPolicy::$retryAfter` kernel amendment, configuration validation, and the four
migrations are independent leaves and may proceed in parallel without weakening that
gate.

The plan carries the settled security boundaries rather than reopening them:

- Submitted identifiers, including nonexistent ones, advance identifier state
  identically. Only that dimension may lock.
- The current six-digit OTP/TOTP fixed-boundary online-guess target is at most
  `10^-4` per submitted identifier.
- IP counts distinct submitted identifiers, deduplicated by `(IP, identifier)` tuple;
  it never counts repeated failures from one subject as new breadth.
- IPv6 `/64` and IPv4 observe at 30/300 distinct subjects initially. Shared dimensions
  default to observe, tenant/global enforcement defaults null, and no shared dimension
  can emit lockedUntil.
- Identifier state commits before advisory state. A crash can under-count shared
  evidence but cannot erase the authoritative failure, and no arithmetic invariant
  may reconcile counters that measure different units in separate transactions.
- Shared lock wait is fixed at one second and restores the host connection's prior
  setting. Verified contention skips only that advisory dimension; unrelated database
  errors stay loud.
- Scalar retention defaults to 86400 seconds; tuple markers live for one database-clock
  window. `vouch:prune` never touches persistent enrollment locks.
- Observe-mode reporting is aggregate-only on both sides: no subject output and no
  candidate-lookup input.

**Code-grounded planning finding and Phase 2.3 correction.** Production `AuthFlow`
currently never calls `Factor::challenge()`; its similarly named calls only build
`ScreenSpec`, and every real OTP issuance call is in driver tests. Email/SMS OTP is
therefore not end-to-end functional despite being registered and advertised by config.
The issuance-cap task owns the corrective production hook as well as its limit. A
counter around screen construction is vacuous. The task must preserve the driver's
no-silent-target rule and the parent spec's unknown-identifier decoy/no-delivery
posture; if current request and screen types cannot express a safe target, the
implementer stops for a narrow design amendment rather than choosing a credential or
turning ambiguity into a public 500.

**Inherited evidence that must change, not disappear.** The lockout/retry architecture
tests, strict retry-null HTTP tests, EnrollmentGuard wait-bound test, kernel API
snapshot, and `AuthChallenge:39` mutation ruling each describe the pre-2.3b boundary.
The plan assigns their replacements explicitly. Deleting any of them is not completion.

### Task 14 production OTP issuance — 2026-08-16

Email and SMS OTP are now reachable through the production authentication flow. One
target-free `ChallengeIssuer` charges issuance before identifier resolution, resolves
exactly one server-owned credential or a durable decoy, and owns the sole production
factor-challenge call. Identify plus first challenge costs one event; resend and factor
switch cost one additional event; screen rendering costs none. Known and nonexistent
identifiers each receive exactly five admitted issuances per 900-second window and the
sixth returns the same shaped refusal.

Challenge and delivery state commit atomically. The outbox encrypts the exact issued
code and verified destination snapshot, while the queued job contains only a random
64-character opaque locator. Changing the persisted identifier after commit does not
retarget the queued code. The queue boundary rejects synchronous, deferred,
background, null, and mixed failover configurations through their resolved queue
types before charging or writing state. A scheduled redispatch command recovers the
commit-before-push window without extending the database-clock challenge deadline.

Workers retry the same encrypted code rather than invoking a generator. Provider
success, permanent failure, expiry, and exhausted retries all clear ciphertext;
missing or swept rows are idempotent success. Decoys perform the same request-side
counter, credential-query, challenge, outbox, and dispatch work but delete their row
without provider contact and can never verify. An ambiguous set of active targets is
also a decoy rather than first-target selection, fan-out, or a public exception. The
named 2.3c delivery-economics seam is implemented after volume permission and target
resolution but before the factor call; it performs authoritative reservation and
CAPTCHA escalation.

The focused gate is **95 passed / 417 assertions**. The persistence-sensitive subset
is **35 passed / 187 assertions** on each of file-backed SQLite, MySQL 8, and
PostgreSQL 16, including the existing-window issuance contention case. Manual probes
separately reject removal of target-independent charging, first-target selection,
outbox transactionality, terminal payload clearing, asynchronous-queue enforcement,
and PostgreSQL row locking. Ordinary gate: **948 passed / 25 skipped / 3,285
assertions**; PHPStan level 9 clean; Composer validation and `git diff --check` clean.

The two planned historical negative-control tests were not retained. That process
deviation remains visible in the implementation plan: the endpoint test is
discriminating against the pre-fix source, while transaction rollback and
request-path isolation are probed directly against the final boundary. Task 17 still
owns authoritative mutation regeneration and disposition of any rows introduced by
this task.

### Task 15 pruning and aggregate reporting — 2026-08-16

`vouch:prune` now takes one database-clock snapshot and commits one transaction over
expired attempts and their challenges, retained revoked sessions, scalar throttle
counters, expired identifier locks, tuple markers, and expired OTP outbox rows. Tuple
markers use the 900-second window boundary; scalar state uses the configured
86400-second retention floor; active locks, persistent IP-window parents, and
enrollment-lock rows survive. Outbox ciphertext is classified and removed at its own
deadline, independently of throttle retention.

The command has three disjoint exit meanings. Status `0` is a successful sweep with
no expired-undelivered work, `1` is a prune failure whose transaction rolled back, and
`2` is a successful committed sweep that found expired-undelivered OTP work. Tests
inject a failure after earlier deletes have executed and prove rollback, while the
status-`2` case proves every deletion category committed and every emitted count is
exact. `VouchPruneSchedule` preserves those meanings through Laravel scheduling:
`0` and `2` complete normally, `2` alone routes the aggregate to delivery-worker
health, and `1` or an unknown value throws. The operations note forbids direct
`Schedule::command(...)->onFailure(...)`, which would collapse the last integration
boundary back to binary success/failure.

`vouch:throttle:report` exposes only aggregate active-bucket totals, fixed
distribution bands, threshold-crossing counts, and current OTP outbox health in human
or JSON form. Its command signature and underlying reporter accept no subject
parameter, every candidate-style option is rejected behaviorally, and the rendered
report contains no identifier, IP, tenant, digest, tuple, target, or credential.
Expired rows disappear from current aggregates after prune; the prune output and exit
status remain the event signal rather than fabricated historical telemetry.

One cross-engine defect was caught before commit: `current_time` was not a portable
column alias for the database-clock query on MySQL. `DatabaseTime::current()` now uses
the package-specific `vouch_current_time` alias and the final report/prune gate passes
unchanged on file-backed SQLite, MySQL 8, and PostgreSQL 16. A second fixture trap was
removed: DDL used to induce prune failure implicitly committed MySQL's Testbench
savepoint, so rollback is now probed with a portable query-boundary fault instead.

Focused gate: **23 passed / 155 assertions** on each database engine for prune,
scheduler adaptation, and aggregate reporting. Expanded provider/OTP gate:
**95 passed / 272 assertions**. Ordinary gate: **973 passed / 25 skipped / 3,438
assertions**; PHPStan level 9 clean. Manual probes separately reject changing exact
OTP or outbox expiry from `<=` to `<`, removing the prune transaction, and collapsing
all expired outbox rows into the delivered class. Task 17 still owns the authoritative
mutation regeneration and survivor disposition for expressions introduced here.

### Task 16 package and architecture boundaries — 2026-08-16

Every 2.3b service now has an explicit container binding, including the identifier and
IP canonicalizers that Laravel previously autowired only as dependencies of
`ThrottleKey`. The binding test uses `bound()` rather than successful resolution:
removing a concrete-class registration still lets Laravel construct the class, so a
resolution-only assertion would certify an implicit contract the provider never
made. The singleton inventory includes every throttle, issuance, outbox, and
canonicalization service.

The temporary lockout convention is replaced by source-wide structural controls.
Exactly four `RetryPolicy` constructions exist, owned only by `ScreenBuilder` and
`ErrorShaper`. `DatabaseAuthThrottleStore::writeLock()` is private and has one call
site inside `recordIdentifierFailure()`; shared state has no `lockedUntil` property,
and its only screen branch writes `lockedUntil: null`. Lock-table access is limited to
the identifier store plus deletion-only pruning.

The HTTP trust boundary is exact: `AuthController` performs the one request IP read,
downstream flow code consumes `FlowRequest::$clientIp`, and no production file reads a
forwarding header. Throttle migrations reject raw identifier/IP/tenant/subject
columns, HMAC and APP_KEY access are scanned across both source and config, and
throttle/report code cannot log directly. Imported and fully-qualified scanner
fixtures prevent the near-miss previously recorded on `RetryPolicy`.

The public endpoint now proves the disclosure rule with the real store. Retry remains
null before a deadline is measured; after cumulative backoff, known and nonexistent
identifiers both emit the same strict error and the same retry field shape, with
`attemptsRemaining` and `lockedUntil` redacted and only `retryAfter` populated. The
test deliberately reads the sixth failure: the fifth failure's one-second deadline
may already be spent by verification and the database's second-precision clock, and
publishing an expired deadline would be fabricated state.

One stale provider assertion was corrected rather than implemented: only
`ValidatesVouchSession` belongs in the global web group. `RequireAssurance` is
route-scoped because each route supplies the required level; its exact alias remains
separately pinned. Public operations documentation now records APP_KEY rotation,
TrustProxies ownership, observe-mode shared dimensions, opt-in tenant/global
enforcement, aggregate-only reporting, and the Phase 2.4 audited-unlock dependency.

Focused architecture/provider/endpoint gate: **107 passed / 214 assertions**.
Ordinary gate: **1,000 passed / 25 skipped / 3,522 assertions**; PHPStan level 9
clean. Source-level probes reject a fully-qualified retry construction, a downstream
request-IP read, a forwarding-header read, a raw identifier throttle column, and
removal of an explicit canonicalizer binding.

### Task 17 authoritative mutation reconciliation — 2026-08-19

The patched full-scope run completed without truncation: **2,572 mutations / 81
files / 81 RUN / 0 kernel / 0 fatals / 0 `No tests found` / 324 untested / 68
uncovered / 4 timeout / 2,176 tested / 84.76%**. Its 396 emitted rows collapse to
266 `(file, mutator, expression)` groups. Every group has one explicit ledger
entry in `docs/superpowers/mutation/2026-08-19-task17-survivor-ledger.md`; there
are no unassigned or double-claimed groups, and no file gained survivors from
the preceding authoritative run.

The ledger keeps four timeout mutants separate, names the matrix-backed locking
rows without relabelling them equivalent, and preserves direct behavioral probes
when the mutation runner reports an attribution gap. The full suite is green on
all three engines: file-backed SQLite **1,110 passed / 3,909 assertions**, MySQL 8
**1,110 / 3,911**, and PostgreSQL 16 **1,110 / 3,913**. The IP contention suite is
10 tests / 59 assertions on each engine. Removing the IP parent `lockForUpdate()`
fails the committed-parent cell on PostgreSQL and passes on file-backed SQLite,
proving that the lock is load-bearing on the engine where SQLite cannot observe
it. PHPStan level 9 is clean. Pint is unavailable in this checkout, so style
remains unverified rather than claimed clean. The branch is clean and remains
unmerged pending the branch owner's decision.

The recovery-boundary test was made deterministic after the first MySQL run
exposed a one-second wall-clock race; this was a flake detector, not an engine
semantic difference. The aggregate report has a separate premise: column reads
return native integers on the supported PDO drivers, while `SUM()` may return a
numeric string and is normalized explicitly.

---

## 2.3d — planned: account lifecycle (Fortify parity)

Plan: [`docs/superpowers/plans/2026-08-19-vouch-phase-2-3d-account-lifecycle.md`](docs/superpowers/plans/2026-08-19-vouch-phase-2-3d-account-lifecycle.md)

**Why it exists.** The package people compare Vouch to is Fortify. Vouch already does
login, two-factor and password confirmation better; it is missing the lifecycle around
them. All four gaps are compositions of the OTP factor, the encrypted outbox, recovery
grace, and driver `enroll()` — parity work, not a new phase of invention.

**Task 1 is an install cliff, not a feature gap.** `AuthFlow` resolves identifiers with
`whereNotNull('verified_at')` and nothing shipped sets that column, so a fresh install
cannot log anyone in and the refusal is deliberately undiagnosable. Until it lands, the
package is unusable by anyone who has not read the source.

| # | Task | Effort | Deps | Issue | Status |
|---|---|---|---|---|---|
| 1 | Identifier verification subsystem | **L** | — | — | Planned |
| 2 | Credential recovery (password reset) | M | 1 | — | Planned |
| 3 | First-credential enrolment service | S | 1 | — | Planned |
| 4 | Credential self-service | M | 2 | — | Planned |
| 5a | Authorization integration survey | S | — | — | **Complete** |
| 5b | Ability → assurance requirement map | M | 5a | — | **Complete** |
| 6 | Suggest `spatie/laravel-permission` + composition recipe | XS | 5b | — | **Complete** |
| 7 | Positioning: tagline and non-goals above the fold | XS | — | — | **Complete** |

**Revised after review.** Task 1 is new machinery, not composition: the OTP outbox
deliberately refuses unverified identifiers, and `auth_challenges.attempt_id` is a
non-null foreign key, so a verification has no attempt to belong to. It needs its own
attempt-independent store and type-level purpose separation, on the `BindingDomain`
precedent, so a verification code cannot be redeemed as a login factor.

**Sequencing decision recorded.** The 2.3c delivery-economics implementation is now
present, including its reservation and CAPTCHA controls. The remaining 2.3c exit work
is evidence review and the lock-mechanism write-up; the next feature track is 2.3d
Task 1's identifier-verification ceremony, followed by the rest of 2.3d.

**Decisions recorded in this phase.**

- *Authorization stays out of scope.* `spatie/laravel-permission` is suggested, never
  required. A library requiring another library it does not itself call imposes an
  architecture decision on every consumer, inherits its release cycle, and would double
  the surface this package has to defend for near-zero differentiation.
- *The composition is made safe instead.* An ability→assurance map keyed on ability names
  works with Spatie, Bouncer or plain Gates, and closes the gap where a developer writes
  `permission:invoices.approve` and forgets `vouch.assurance:aal2`. Enforced centrally so
  route middleware is not the only covered path; deny-only so it can never become an
  authorization bypass; and insufficient assurance sends the user to step up rather than
  returning a bare 403.
- *Credential change cannot be one transaction.* Revocation must survive a failed
  mutation, and a rollback would undo both. Chosen order: commit revocation, then
  mutate separately, then revoke again — the second pass is idempotent and closes the
  window in which a login with the old credential creates a session the first pass
  never saw. The residual, a session created inside that window when the second pass
  also fails, is recorded rather than presented as impossible.
- *Password reset defaults to honest reduced assurance.* Inbox control is one
  possession factor and is recorded as such, so per-route step-up still guards
  sensitive actions. Requiring the second factor during reset is configurable and
  tested; full assurance from inbox control alone does not ship.
- *Grace capability is a separate axis from the assurance ladder.* `AssuranceComparator`
  returns false for any grace session, so "every self-service operation requires
  step-up" would make recovery self-service impossible by construction. The operation
  matrix in the plan states which operations grace may perform.
- *The name implies authorization and the fix is a tagline, not a subsystem.* Vouching is
  attestation — a referee vouches for you, they do not hire you — which is exactly what
  the assurance record is. Renaming is cheapest now, while unreleased and undepended-on,
  so the decision point is here if it is ever going to be taken.

---

## post-2.4 — planned: impersonation

**Why it belongs in Vouch rather than an authorization package.** `auth_sessions`
carries exactly one `user_id`, and assurance is derived from the session. Impersonation
gives a session two principals — the actor and the subject — so bolting it on outside
Vouch, the way the existing impersonation packages do (swap the guard's user, stash the
original id), makes the assurance layer silently read the wrong principal.

Four things break quietly under that approach:

- `RequireAssurance` reads the subject's `acr`, so an impersonated session either blocks
  a staff member who did do MFA, or inherits an assurance level the subject earned and
  the actor did not.
- `Vouch::stepUp()` challenges the subject's factors, which the actor does not possess —
  step-up during impersonation becomes impossible rather than merely awkward.
- Revoking the subject's sessions has no defined effect on an impersonation.
- `AssuranceComparator` returns false for any grace session, so an impersonated grace
  session has no meaning at all.

**Boundary.** Vouch owns the mechanism and the invariants; the host owns whether this
person may impersonate that person, including any role-hierarchy rule — Vouch does not
know what a role is. Same seam as `TenantResolver`: the host checks, then calls, and
Vouch enforces safety rather than permission. The authorization half is already
anticipated by 2.3d Task 5b's example, `'users.impersonate' => 'aal3'`.

**Gated on 2.4.** "Staff member X acted as customer Y between 14:02 and 14:19" is the
highest-value audit event this package will produce, and `AuditSink` does not exist
until 2.4. Shipping impersonation without an audit trail is worse than not shipping it —
the same reasoning that deferred the recovery-code notification.

**Vouch has no concept of hierarchy, and must not pretend otherwise.** It cannot answer
"is this user below that one", because it does not know what a role is. That makes the
safety of the whole feature rest on a predicate only the host can supply, so:

- *The host predicate is required, not optional, and there is no permissive default.*
  Impersonation is unavailable until the host binds something that answers "may A act as
  B". `NullTenantResolver` returning null is a safe default; a null impersonation policy
  returning true would be catastrophic. This follows `AuditSink`: unbound and throwing,
  so absence fails loudly rather than silently permitting.
- *The capability matrix is the mitigation for the blind spot.* Vouch cannot judge who
  may impersonate whom, but it can bound what impersonation *is*. A read-only default —
  may view, may not change credentials, may not mint tokens, may not impersonate further
  — limits the blast radius even when a host predicate is wrong.

**Role impersonation is out of scope.** "View this as if I were an Editor" changes no
identity: `user_id` is unchanged, you are still yourself, only what `can()` returns
differs. That is entirely the authorization layer's business and is a few lines in a host
app. One rule regardless of who builds it: it must be **downgrade-only**, constrained to a
subset of the actor's own effective permissions. "View as Admin" from a lesser role is a
privilege-escalation feature with a friendly name.

**Design questions to settle first.**

1. *The two-principal session model.* How a session represents "acting as X, actually Y";
   which principal assurance derives from (the actor, since they are the human who proved
   something); how step-up targets the actor's factors while the session reads as the
   subject; and what revoking either principal's sessions does.
2. *The capability matrix*, on the recovery-grace precedent — a capability axis separate
   from the assurance ladder. "The actor proved aal3" is not the same claim as "aal3-gated
   actions are appropriate as this subject", and many deployments want impersonation to be
   effectively read-only. Starting position: may view; may not change credentials; may not
   mint tokens; may not impersonate further.
3. *Non-recursion, bounded lifetime, and return-to-self* surviving deletion or revocation
   of the subject.
4. *Exposing both principals to the authorization layer.* During impersonation, whose
   permissions apply — the subject's alone, or the intersection of actor and subject? The
   subject's alone is what most implementations do and is the escalation footgun: a
   support agent impersonating an admin acquires admin powers. The intersection is safer
   but cannot always reproduce the user's experience, since a bug needing a permission the
   actor lacks becomes unreproducible. Vouch cannot take that decision, having no view of
   roles — but it must publish both principals as a read-only signal so the host can. The
   deny-only rule on the 2.3d assurance map means no grant path, impersonation or
   role-switching, can route around an ability's assurance requirement.

This also replaces a package rather than adding one: existing impersonation packages do
not touch assurance, so they cannot do step-up or honest audit.
