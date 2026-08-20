# Phase 2.3c — OTP delivery economics and CAPTCHA

## Goal

Complete the delivery-economics boundary reserved by `ChallengeIssuer`:

- SMS country allow-lists;
- per-tenant spend ceilings;
- daily spend limits;
- a provider-independent CAPTCHA contract;
- adversarial tests proving that economics can refuse delivery without
  recounting authentication volume or reaching an OTP factor.

2.3c does not redesign authentication throttling. Volume permission remains the
2.3b decision and runs first. The 2.3c decision runs only after a server-owned
target has been selected and immediately before the factor challenge call.

## Non-negotiable boundaries

1. `ChallengeIssuer` remains the sole production caller of `Factor::challenge()`.
2. Economics receives delivery metadata, never a resolved user as its policy key.
3. A refusal is target-independent in its externally visible shape and never
   refunds or re-counts the 2.3b issuance event.
4. The CAPTCHA contract is verification-only: no provider, token secret, or
   challenge implementation ships in this phase.
5. SMS country is derived from the verified identifier target; email delivery
   does not enter the SMS country policy.
6. Spend accounting is delivery-facing state and is separate from authentication
   issuance volume. It must not be used as a substitute for the 2.3b counter.
7. No synchronous provider work is introduced. Economics must complete before
   the existing encrypted outbox path and cannot make the request path contact
   a provider.

## Dependency order

### 1. Contracts and immutable intents

- Add a delivery-economics contract with an immutable target-bearing intent.
- Add a typed decision/result that distinguishes permitted delivery from an
  economics refusal without nullable combinations.
- Add a CAPTCHA verifier contract with an immutable verification request/result.
- Add an explicit unconfigured implementation that fails closed; do not bind a
  permissive no-op.
- Extend `ChallengeIssuer` at the existing named boundary only.

Focused proofs:

- economics refusal reaches no factor and leaves the issuance counter unchanged;
- permitted economics reaches exactly one factor challenge;
- missing economics binding fails before provider work;
- CAPTCHA is never called for non-escalated delivery and a failed verification
  cannot be treated as success.

### 2. Delivery metadata and canonical policy inputs

- Carry channel, verified identifier type/value metadata, tenant identity, and
  configured delivery cost in the intent.
- Normalize SMS country through one canonical parser boundary; do not infer it
  from arbitrary request headers or a second IP/proxy lookup.
- Keep tenant absence distinct from an empty tenant identifier.

### 3. Economic state and atomic decisions

- Add delivery-facing persistence for daily/tenant spend and country decisions.
- Use database-clock deadlines and atomic SQL updates/inserts; no PHP
  read-modify-write.
- Prove same/different tenant and same/different country contention on all three
  engines where the database semantics matter.
- Keep delivery accounting independent from authentication-volume transactions;
  under failure, under-counting is safer than collateral over-counting.

### 4. CAPTCHA integration

- Define the escalation point without adding a 2.3b CAPTCHA rung retroactively.
- Verify CAPTCHA before a delivery is permitted, after volume permission and
  before the factor call.
- Preserve strict-posture response shape and never expose provider diagnostics or
  account existence through CAPTCHA refusal.
- Add architecture coverage preventing a direct provider/CAPTCHA call from the
  flow or factor drivers.

### 5. Operational reporting and reconciliation

- Extend aggregate reporting without emitting identifiers, addresses, candidate
  lookup inputs, or provider secrets.
- Update prune retention for delivery-economic state separately from OTP payload
  retention and throttle state.
- Re-run the three-engine suite, PHPStan, Pint if available, and the mutation
  manifest for all new source expressions.

## First implementation slice

The first commit should contain only the contracts, unconfigured fail-closed
implementations, the issuer seam, and focused tests. It must not add a permissive
default or persistence whose policy has not yet been exercised.
