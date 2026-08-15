# Phase 2.3b/2.3c — §7.4 Scope Amendment

**Status:** Decided 2026-08-15. No implementation or new runtime contract lands in
this amendment.

## Split

§7.4 originally travelled as one item, but it combines two systems with different
authorities and inputs:

| Slice | Owns | Does not own |
|---|---|---|
| **2.3b** | Authentication throttling: limits over the submitted authentication request, exponential backoff, lockout, challenge-attempt caps, and the measured `RetryPolicy` presented by the existing flow | OTP delivery economics and CAPTCHA |
| **2.3c** | OTP pumping and delivery-fraud controls: send caps, per-tenant spend ceilings, SMS country allow-lists, daily limits, and the CAPTCHA contract | Login lockout and its response disclosure |

The split keeps the strict-posture enumeration boundary with the flow that consumes
it. Delivery fraud needs information the current `OtpDelivery` contract does not
carry — country, spend, provider outcome, and a cost authority — so it must not be
smuggled into authentication throttling as an unexamined counter.

## Frozen 2.3 contract that 2.3b consumes

`RetryPolicy` and `ErrorShaper` are Phase 1 kernel code and remain unchanged. Their
contract already decides disclosure: `Outcome::Locked` is shaped in full in every
posture, including strict, and is safe only if known and unknown submitted
identifiers are throttled identically. 2.3b populates that existing shape; it does
not redesign it or modify `src/Kernel`.

2.3's explicit `retry: null` is therefore not a placeholder to delete. It records
that no retry state has yet been measured. 2.3b must replace the endpoint and
strict-posture assertions with proof that a populated policy is safe for both known
and unknown identifiers. `LockoutBoundaryTest` must be rewritten at least as
strictly as its current fully-qualified-name-aware scan; it must not be removed.

## CAPTCHA ladder

2.3b's escalation ladder stops at backoff and lockout. It has **no CAPTCHA rung**
and no dependency on a not-yet-defined provider contract. CAPTCHA belongs to 2.3c,
where delivery risk and provider verification can be designed together.

## Counter substrate — deferred design decision

There is no current counter store. 2.3b must decide explicitly whether to build an
authentication-specific store or a general primitive keyed by an arbitrary subject.
An auth-specific store is permitted, but the design must name its retrofit cost for
2.3c rather than imply that it is reusable.

Before code, the design must also settle what is counted and where. The
enumeration-safe input is the **submitted identifier**, never a resolved user record:
counting only found accounts makes both timing and lockout behaviour an
account-existence oracle under strict posture.

## Inherited mutation re-ruling

`AuthChallenge::$attempts` currently has no consumer. Its integer cast was
dispositioned equivalent only under that present fact. 2.3b gives the field its first
reader/writer for challenge caps, so the disposition is no longer inherited: the
counter's type, increments, threshold boundary, and invalidation semantics require
their own tests and mutation review.
