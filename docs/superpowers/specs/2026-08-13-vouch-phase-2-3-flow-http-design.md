# Phase 2.3 — Flow and HTTP Surface: Design Specification

**Date:** 2026-08-13
**Status:** Approved design, not yet implemented
**Parent spec:** [`2026-08-11-vouch-design.md`](2026-08-11-vouch-design.md)
**Depends on:** Phase 1 (`Vouch\Kernel`), Phase 2.1 (persistence), Phase 2.2 (factor drivers) — all merged

---

## Scope

2.3 is the first slice that logs anyone in. It delivers the flow orchestrator, a JSON HTTP
surface, `ScreenSpec` rendering, session lifecycle, recovery-grace enforcement, and
`RequireAssurance` in its interactive mode.

### What was split out, and why

The parent roadmap listed 2.3 as "orchestrator, routes, `ScreenSpec`→JSON,
`RequireAssurance` both modes, rate limiting (§7.4)". That bundles independent subsystems,
and one of them has a dependency running backwards.

| Moved to | What | Why |
|---|---|---|
| **2.3b** | §7.4 abuse controls and rate limiting, entire | Its own data model, cost controls and adversarial tests. Per-identifier send caps, per-tenant spend ceilings, country allow-lists and hard daily limits are an anti-fraud subsystem the orchestrator *calls*, not a feature of it. |
| **2.4** | `RequireAssurance` non-interactive mode (RFC 9470) | It is default-deny against `auth_token_assurances`, and nothing writes those records until 2.4's `Vouch::issueToken()`. Building the enforcement half first means testing it only against hand-written fixture rows, and shaping enforcement to fit fixtures rather than to fit what issuance produces. |
| **A post-2.4 slice** | Remember-me (§7.5 device-bound persistent login) | A persistent bearer credential is a separate authentication system: rotation, reuse/theft detection, revocation, device lifecycle. Its ceiling — never above `knowledge` strength — must be expressed against 2.4's token-assurance machinery rather than invented alongside it. |

Session lifecycle and recovery-grace stay **in** 2.3 deliberately: they are inseparable from
the flow that creates, rotates and enforces sessions. Splitting them would put an invariant
in one phase and its enforcement in another.

The resulting sequence: **2.3** login flow, HTTP/presenter, session/grace, interactive
step-up → **2.3b** abuse controls → **2.4** token issuance/audit plus non-interactive
assurance enforcement.

---

## The HTTP surface ships JSON only

Routes return `ScreenSpec` as JSON. That is the product. `vouch-ui` (Phase 3) and host
applications render it.

This creates a real risk the design must answer: `vouch-ui` lands *after* all of Phase 2, so
without intervention the `ScreenSpec`→JSON contract would be frozen in 2.3 with **zero**
renderers exercising it, then discovered wrong in Phase 3 after 2.4, 2.5 and 2.6 had built
on it. §8.3 says outright that the second adapter "is what reveals what the first one baked
in wrongly" — with no first adapter, nothing reveals anything.

### The test-only reference renderer

2.3 ships a minimal Blade renderer that lives in `tests/`, consumes `ScreenSpec` as an
independent client, and is driven **through the real routes** — not by calling the builder
directly. It covers every screen, every error, and every escaped value.

It is **not published, not routeable, and not container-registered in production.** It is a
consumer that makes the contract earn its stability before Phase 3, not a UI story.

Asserting JSON shape alone would test the serializer against itself, with no independent
consumer — the shape that produced this project's vacuous controls. Escaping coverage
matters specifically: §7.1.1's posture-filtered errors must survive rendering without
becoming an injection surface.

---

## Attempts are always bound

Every attempt is created with a non-null `bound_context` derived from the host session. An
attempt cannot be started without one.

**The handle identifies the attempt; it must not also function as its bearer credential.**
2.1 built `auth_attempts.handle` as unique and opaque, and `DatabaseAttemptStore` returns
`ContextMismatch` when the stored and presented contexts disagree — but `bound_context` is
nullable and the comparison is equality, so two nulls match and an unbound attempt is
completable by anyone holding the handle. Requiring binding at creation is what makes
`ContextMismatch` a genuine security invariant rather than a conditional one.

Cookieless and machine clients stay on the token path (§6.2), which is the correct flow for
them, rather than silently weakening browser flow security.

**The invariant is enforced at runtime, on attempt creation and on every advance** — not by
a boot-time assertion about middleware. Middleware configuration can change after boot; the
runtime check must remain authoritative. Registration inside the host's `web` group is a
convenience default, not the guarantee.

---

## Architecture

Five units, each with one job.

**`Flow\AuthFlow`** — the orchestrator, and the only component that knows the shape of an
authentication attempt. Given a bound attempt and the current input it resolves policy, asks
the `FactorRegistry` for the driver, hands the driver a `VerificationRequest`, passes the
returned `SingleUseMutation`s to `AttemptStore::transition()`, and evaluates satisfiability.
It is **not** HTTP-aware: no request, response or session types cross into it.

**`Flow\ScreenBuilder`** — turns flow state into the kernel's `ScreenSpec`. This is where
"which factors to offer" is decided, once, per §8.2. Every error it places on a `ScreenSpec`
has already been through the kernel's `ErrorShaper`; nothing else in Phase 2 may construct a
user-visible authentication error.

**`Http\AuthController`** — one action. Translates HTTP into a flow request and a
`FlowResult` into JSON. It contains no branching on `AuthStep`; if it grows a `match` on
state, the boundary has leaked.

**`Sessions\SessionLifecycle`** — owns §7.5: regenerate on assurance increase, rotate the
`auth_sessions` row, revoke siblings on credential change.

**`Recovery\GraceSession`** and its own controller — the constrained capability, reading the
grace record rather than an attempt.

### `FlowResult` — the completion seam

`AuthFlow` returns a typed result, not a bare `ScreenSpec`:

- **`Continue(ScreenSpec)`** — the next interaction.
- **`Authenticated(AuthSuccess)`** — user ID, fresh satisfied factors, AMR/assurance facts,
  and the bound-context key. **No HTTP or session objects.**
- **`RecoveryGraceStarted(...)`** — recovery opened the constrained capability.

A thin result handler dispatches — `Authenticated` to `SessionLifecycle` — and only then
does the controller serialize. Returning only a `ScreenSpec` would force the controller to
infer completion from screen contents, which is exactly the branching the boundary forbids.

**An unhandled `FlowResult` variant must throw.** PHP has no sealed interfaces, which is
why `DatabaseAttemptStore` throws `UnknownMutation` rather than skipping a type it does not
recognise. The same discipline applies here: falling through to "serialize whatever screen
we have" would silently skip session rotation on a successful authentication.

### Two rules the structure enforces rather than documents

- **Transition legality stays in the kernel's `TransitionRules`.** `AuthFlow` asks; it never
  re-derives.
- **`AuthFlow` returns a `FlowResult`, never a redirect or a response.** That is what keeps
  one core driving both the JSON surface and Phase 3's adapters.

---

## The route surface

### `POST /vouch/auth`

Begins when no handle is present, advances when one is. The body carries the handle, the
current screen's action, and its input. The server loads the attempt, validates its current
state, and returns the next result.

**The client never selects a state, a factor transition, or an endpoint.** A client that
cannot name the next step cannot call steps out of order, cannot skip one, and cannot
discover the state machine by probing. Per-step endpoints would publish the machine to the
client and require each endpoint to independently re-derive whether it is legal right now —
four places to get one check right, in a codebase whose recent history says that is where
controls go vacuous. It also means adding passkey in 2.2b or OIDC in 2.5 changes no routes.

The response is a small envelope with an explicit discriminator matching `FlowResult`, so
the client reads an outcome rather than inferring one.

### Grace routes are separate

Recovery enrollment and recovery completion are their own routes. They are a distinct
constrained capability, not steps in an ordinary authentication attempt: `/vouch/auth`
authorizes from the **bound attempt**, grace routes authorize from the **grace record**.
Collapsing them would make one endpoint's guard depend on which of two states it happened to
be in.

### Status codes

**One status — 200 OK — for every well-formed authentication outcome.** That includes
unknown identifier, bad factor input, expired or consumed challenge, invalid handle, illegal
advance, and policy refusal. The envelope discriminator and the shaped `ScreenSpec` carry
the result.

Status is derived from the *shaped* outcome, never the underlying cause. This is the
enumeration boundary in a place that is easy to miss: if a wrong password returned 422 and an
unknown identifier returned 404, strict posture would be defeated by `curl -i` regardless of
how carefully the body was filtered.

**Genuine transport failures keep normal HTTP semantics** — malformed JSON or schema (400),
CSRF failure (419), unsupported method (405). They reveal request validity, not account
state.

### `RetryPolicy` is always null in 2.3

It is filled by 2.3b. Emitting a fabricated retry state now would be a control that reports
something nobody measured.

---

## Session lifecycle

### The fail-closed protocol

Host-session regeneration and the database row rotation use **different stores**. There is no
shared transaction and the design must not claim one. The ordering is the mechanism:

1. Regenerate the host session ID.
2. Rotate or create the server-side record for the new HMAC binding.
3. **Only then** log the user into the host guard.
4. If step 2 fails, destroy the regenerated host session and fail authentication.

Guard login is last precisely so that every earlier failure lands on an unauthenticated
session. A user must never be left guard-authenticated without a matching record.

2.1 already ships rotate-in-place with a test that the row count stays at one, so a
regenerated session finds its record rather than a stale binding.

### Rotation triggers on assurance increase, not on login

§7.5 requires regeneration on **every** assurance-level increase. The trigger is a change in
recorded assurance, not the act of logging in: a step-up that raised assurance without
rotating would leave the pre-step-up session ID valid at the higher level.

### Revocation needs an authoritative read

Setting `revoked_at` changes nothing on its own — the host's session cookie still works.
Revocation without an authoritative read is only a database annotation.

So vouch ships middleware that resolves `SessionBinding::for(session id)` against 2.1's
unique index on every authenticated request and refuses when the row is revoked, missing, or
past its absolute grace expiry. That is one indexed read per request, and it is the correct
price: without it, "all other sessions invalidated on password change" is a documented
promise with no mechanism.

**The middleware is mandatory for host routes whose authenticated state vouch establishes.**
It is appended to the `web` group and **boot fails if it is absent**. A runtime check is
authoritative only on requests that actually traverse it — which is why the bound-session
invariant (enforced inside vouch's own code path) and this middleware (enforced at
registration) are complementary rather than redundant.

Sibling revocation uses 2.1's constrained `RevokedReason` values.

---

## Step-up and `RequireAssurance` (interactive mode)

A route declares the assurance it requires as a middleware parameter. When the current
session's recorded assurance is insufficient, the interactive mode redirects to the step-up
flow and remembers the intended destination.

**Step-up reuses `POST /vouch/auth`.** It is an attempt like any other, distinguished by its
intent: policy is resolved for the step-up intent rather than for login, and because the
session already identifies the user there is no identify step. Reusing the endpoint means
step-up cannot drift away from login in how it validates transitions, shapes errors, or
consumes single-use state — there is one flow, resolved against a different policy.

On success the recorded assurance increases, which is precisely the trigger §7.5 names for
session rotation; the fail-closed protocol runs, and only then is the user returned to the
intended destination.

`Vouch::stepUp($level)` is the imperative entry point for hosts that need to demand
assurance outside a route declaration (§7.5).

**Two interactions worth stating explicitly:**

- **Grace sessions never reach this middleware.** A grace session is not authenticated, so
  the session-check middleware refuses it first. `RequireAssurance` is never the component
  keeping a recovery-grace session out of a protected route, and must not be relied on for
  that — containment is grace's own, described below.
- **The non-interactive mode is 2.4, and the middleware must be shaped for it now.** §6.3
  specifies one policy object with two renderings. The assurance comparison and the decision
  that a request is insufficient belong in a single place that both modes consume, so adding
  the RFC 9470 response in 2.4 adds a rendering rather than restructuring the interactive
  path. Building the comparison inside the redirect branch would guarantee that restructure.

---

## Recovery-grace

Grace needs no new schema. 2.1's `auth_sessions` already carries `user_id`, `amr`,
`recovery_grace_expires_at` and `isRecoveryGrace()`, and binds via the HMAC of the host
session ID — which still exists while that session is anonymous.

**During grace, the bound context stays the host's anonymous session, and the host guard's
login mechanism is never called.** A grace record is therefore an `auth_sessions` row bound
to an unauthenticated session: vouch knows who it is, the host guard does not. Vouch's
server-side grace record authorizes only vouch's own recovery and enrollment endpoints.

This makes a stolen recovery code a **constrained recovery capability, not a broadly
authenticated application session.** Containment is by construction rather than by the host
remembering to apply a middleware.

### Completion

Completion requires **fresh, non-recovery satisfied-factor evidence** — not the mere
existence of credentials on the account. That distinction was a real authentication bypass
caught during 2.1's spec review and must not reappear: possession of a credential is not
proof of control of it.

On completion the fail-closed protocol above runs: rotate, **replace** the `amr` rather than
append, clear the grace expiry, then authenticate to the guard.

### Expiry

Absolute at 15 minutes by default, checked per request by the session middleware, never
extended by activity, and it does not restore the consumed code.

### No persistent artifacts

A grace session mints no API tokens and creates no persistent artifact — no remember-me, no
device trust. Remember-me does not exist yet; writing the prohibition now means the invariant
is already load-bearing when the feature it constrains arrives, rather than being retrofitted
onto a system that already violates it.

---

## Last-factor protection is deferred, and defined here

§7.3 requires that a user cannot delete or disable their only remaining credential. 2.2 gave
drivers `revoke()` but nothing enforces the floor, and **2.3 ships no credential-management
surface to enforce it on.**

Deferring is safe *only* because of that. Therefore:

- 2.3 **neither calls nor exposes `Factor::revoke()`.** This is arch-testable and must be
  enforced as a constraint, not an intention.
- Last-factor protection is a **hard prerequisite for the first credential-management API or
  UI**, in whichever phase that lands.

**When designed, "last factor" means the last active, non-recovery credential set that can
satisfy the resolved login policy — not merely the last database row.** A naive
`count() > 1` check would let a user delete the TOTP their policy requires while keeping a
password, and lock themselves out with a green test suite.

---

## Errors and the enumeration boundary

The kernel's `ErrorShaper` is the sole disclosure boundary. 2.2's drivers report truthfully
— `NoCredential` distinct from `Mismatch`, `BindingMismatch` distinct from both — and
`ScreenBuilder` is where those become user-visible, always through `ErrorShaper` under the
tenant's posture.

The single-200 rule closes the status-code channel. It does **not** close the timing channel.

### Credential-verification timing equalization

Under strict posture, an unknown identifier returns as fast as the lookup while a known one
costs a full verify. That difference is measurable over a handful of requests and
reconstructs exactly the account-existence oracle strict posture exists to deny — so careful
body filtering and a uniform status code would both be defeated by a stopwatch.

**In 2.3, not deferred to 2.3b.** This is enumeration resistance, not abuse control;
deferring it would ship a strict posture that leaks through its primary path.

- **Conditional on strict posture.**
- **The dummy digest must come from the active Laravel hasher.** A hard-coded bcrypt digest
  checked by an Argon-configured hasher is rejected immediately, so the mitigation would
  return *faster* than the real path and silently invert the leak it was added to close.
- **Test the work performed, not wall-clock duration.** Inject or spy on the hash verifier
  and prove that both the unknown-identifier and known-password-mismatch paths execute
  exactly one appropriately configured verification. A duration assertion would be flaky in
  CI and would pass or fail for reasons unrelated to the control.

**Documented boundary, stated honestly:** this equalizes the credential-verification branch.
It does not promise end-to-end constant time.

Two things deliberately left alone: recovery's up-to-ten comparisons leak only *which* code
matched, which buys an attacker nothing; and full constant-time guarantees across the whole
flow are not achievable and not worth pretending to.

---

## Testing

Real databases across SQLite, MySQL and Postgres, as 2.1 and 2.2 established.

Beyond per-unit coverage, the suite must pin:

- **The reference renderer** driving every screen, error and escaped value through the real
  routes as an independent consumer.
- **The verifier spy** proving strict-posture equalization by invocation count and
  configuration.
- **Fail-closed injection** forcing record rotation to fail and proving the regenerated
  session is destroyed and authentication refused. Untested, that branch is the one that
  leaves someone guard-authenticated with no record.
- **Boot failure** when the session-check middleware is absent from `web`.
- **Concurrent advance** on one attempt. The store's CAS already handles it; the flow is the
  first caller that can actually produce the race.
- **Unbound attempt refusal** at both creation and advance, independent of middleware
  configuration.
- **Grace containment** — that no host route is reachable during grace, and that
  `auth()->user()` is null throughout.
- **An unhandled `FlowResult` variant throws** rather than falling through.

Every guard must be demonstrated failing against a deliberate violation before being
trusted, per the discipline established in Phases 1, 2.1 and 2.2.

---

## The mutation gate

Phase 2.2 shipped with `composer mutate` scoped to `--class="Fissible\Vouch\Kernel"`, which
that phase never touched — so its scores were evidence about code it did not write. Ten
assertions that could not fail were found across 2.2, most of them in Phase 2 code the
mutation runs never see.

2.3 establishes the gate for non-kernel code:

- **Define the non-kernel source scope and exclusion list in config *before* the first run.**
  No later narrowing to improve the score. This is the anti-gaming constraint and it is the
  difference between a floor and a rationalization.
- **Run both full and covered passes**, as for the kernel. `--covered-only` must not become
  the sole gate.
- **Audit every initial survivor.**
- **Commit the exact commands, reports, survivor counts, baseline and floors together** in
  `PROJECT.md`, in the shape the cross-engine verification record uses.
- **Set each floor to a conservative whole-number value at or below the audited baseline.**
- **Any later reduction is a security decision requiring explicit review**, never
  implementation convenience.

No number is invented now; inventing one would be guessing, and setting none would let the
gate quietly not exist.

**The gate may be established during 2.3, but 2.3 cannot be declared complete until it is
committed and green.** This is a completion gate in the same sense as 2.2's cross-engine
matrix.

---

## Out of scope for 2.3

- **Rate limiting and abuse controls (§7.4)** — 2.3b, including OTP pumping and SMS toll
  fraud defenses.
- **`RequireAssurance` non-interactive mode / RFC 9470** — 2.4, where token assurance
  records are issued.
- **Token issuance and audit sinks** — 2.4.
- **Remember-me** — a post-2.4 slice.
- **Credential management, and with it last-factor protection** — unowned; defined above as a
  prerequisite for whichever phase introduces the surface.
- **Passkey** — 2.2b. **OIDC** — 2.5.
- **UI adapters** — Phase 3. The test-only reference renderer is not an adapter.

---

## Decision log

| Decision | Choice | Rationale |
|---|---|---|
| 2.3 scope | Split; §7.4 to 2.3b, RFC 9470 to 2.4, remember-me post-2.4 | Three independent subsystems, one with a backwards dependency on records 2.4 writes. |
| Session lifecycle and grace | Stay in 2.3 | Inseparable from the flow that creates, rotates and enforces sessions. |
| HTTP surface | JSON only | Preserves the vouch/vouch-ui boundary; adapters are Phase 3. |
| Contract validation | Test-only Blade reference renderer through real routes | Asserting JSON shape tests the serializer against itself. Makes the contract earn stability before Phase 3 without shipping a second UI. |
| Attempt binding | Required at creation and every advance, runtime-enforced | The handle identifies the attempt; it must not also be its bearer credential. Two nulls matching made `ContextMismatch` conditional. |
| Route shape | Single `POST /vouch/auth` | Client never names the next step; legality lives once in the kernel's mutation-tested `TransitionRules`. New factors add no routes. |
| Grace routes | Separate | They authorize from the grace record, not the bound attempt. |
| Status codes | 200 for every well-formed outcome; transport failures keep semantics | Differing status by cause defeats strict posture via `curl -i`. 400/419/405 reveal request validity, not account state. |
| `AuthFlow` return | Typed `FlowResult`, not `ScreenSpec` | Gives session rotation an explicit completion seam and keeps the controller free of `AuthStep` branching. |
| Unhandled `FlowResult` | Throws | PHP has no sealed interfaces; falling through would skip session rotation on success. |
| Session rotation | Fail-closed protocol, guard login last | Different stores, no shared transaction. Never leave a session guard-authenticated without a record. |
| Session check middleware | Mandatory, appended to `web`, boot fails if absent | A runtime check is authoritative only on requests that traverse it. |
| Grace containment | Host guard never invoked; anonymous session retained as bound context | A stolen recovery code becomes a constrained capability, not an application session. |
| Grace completion | Requires fresh non-recovery evidence | Possession of a credential is not proof of control of it — the 2.1 bypass. |
| Last-factor protection | Deferred, but defined; 2.3 must not call or expose `revoke()` | Safe to defer only because no deletion surface exists. Defined against the policy-satisfying set, not row count. |
| Timing equalization | In 2.3, strict posture only, active hasher, tested by work performed | Enumeration resistance, not abuse control. A duration assertion would be flaky and prove nothing. |
| Step-up | Reuses `POST /vouch/auth` with a step-up intent | One flow cannot drift from itself; a separate step-up path would re-derive transition, error-shaping and single-use handling. |
| `RequireAssurance` structure | Comparison lives in one place both modes consume | §6.3's two renderings; building it inside the redirect branch would force a restructure when 2.4 adds RFC 9470. |
| Mutation gate | Baseline-then-floor, scope fixed in config beforehand | No invented number; no post-hoc narrowing. 2.3 is not complete until it is committed and green. |
