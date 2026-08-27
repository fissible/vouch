# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
## [0.1.0] - 2026-08-27

### Added
- Add factor kind and ordered strength enums
- Add SatisfiedFactor value object
- Add requirement tree and policy array parsing
- Add satisfiability evaluator with distinctness and independence
- Add policy resolution chain with strictest-posture floor
- Derive assurance facts and levels with injectable vocabulary
- Add attempt state machine transition rules
- Add immutable screen specification value objects
- Shape auth errors by enumeration posture
- Add Laravel package scaffolding and multi-engine test harness
- Add tenancy and audit contracts
- Add identifier and credential tables and models
- Add federation tables with cross-tenant uniqueness constraints
- Add policy and token-assurance tables and models
- Add session table with HMAC binding and constrained revocation
- Add attempt and challenge tables and models
- Add database attempt store with CAS transitions
- Add vouch:prune housekeeping command
- Enforce value bounds on the write path, not just in the schema
- Add otphp, a PSR-20 clock, and the OneTimeSecret wrapper
- Land Phase 2.1 amendments A, B and D plus the enrollment lock table
- Enforce Amendment A's same-user, verified and immutability rules
- Require and validate a challenge's credential target for OTP
- The store owns every single-use mutation (Amendment C)
- Serialize credential enrollment per (user_id, type)
- Add the Factor contract and its value objects
- Add the password and recovery-code drivers
- Add the TOTP driver with an explicit timestep replay guard
- Add the email and SMS OTP drivers
- Wire the five drivers into a shared FactorRegistry
- Require a binding domain when deriving a session binding
- Add the flow's value objects and the typed FlowResult seam
- Add ScreenBuilder as the sole disclosure path
- Add the AuthFlow orchestrator
- Add the fail-closed session rotation protocol
- Make session revocation authoritative with a per-request read
- Decide recovery-grace entirely in database time
- Add the single-endpoint HTTP surface
- Equalize the credential-verification branch under strict posture
- Add interactive RequireAssurance with a safe return target
- Add Vouch::stepUp and prove the return target end to end
- Inject the random source so generator bounds are testable
- Add canonical throttle subjects
- Add measured retry deadline to kernel
- Define throttle configuration
- Add authentication throttle schema
- Define authentication throttle contract
- Persist identifier throttle state
- Observe distinct subjects per IP
- Disclose measured throttle retry state
- Throttle authentication failures
- Cap OTP challenge attempts
- Report and prune throttle state
- Enforce throttle architecture boundaries
- Add 2.3c delivery contracts
- Canonicalize SMS delivery targets
- Audit legacy SMS identifiers
- Classify OTP outbox terminal failures
- Add atomic delivery spend reservations
- Bind delivery economics fail closed
- Enforce delivery economics preflight
- Classify delivery reservation outcomes
- Record spend independently of ceilings
- Make delivery spend reservations idempotent
- Reserve delivery economics in outbox worker
- Report delivery economics aggregates
- Prune expired delivery reservations
- Expose shared captcha requirement
- Bind captcha verification fail closed
- Validate captcha escalation at boot
- Wire shared captcha escalation
- Add vouch doctor diagnostics
- Add the identifier verification ceremony (2.3d Task 1)
- Add credential recovery (2.3d Task 2)
- Add first-credential enrollment (2.3d Task 3)
- Add credential self-service (2.3d Task 4)
- Add the ability -> assurance requirement map (2.3d Task 5b)

### Changed
- Share ensure-and-lock primitive
- Own captcha config in throttle configuration

### Fixed
- Cap the default assurance vocabulary at aal2
- Make composer stan pass so CI actually runs the kernel arch tests
- Reject non-boolean policy flags and pin rejection paths in tests
- Apply strict-boolean policy to leaf user_verified/phishing_resistant
- Enforce all_of guards across nested children and search depth-first
- Reject an empty requirement list in all_of and any_of
- Widen kernel API surface snapshot to symbol-presence granularity
- Exclude recovery factors in fromFactors and cover the empty-evidence recency guard
- Type the contention suite's connection lookup for level 9
- Shorten federated-identity issuer so the index fits MySQL's key limit
- Cross-check ConsumeChallenge's attemptId against the advancing attempt
- Close the empty-code, stale-challenge and credential-type holes in the factor drivers
- Anchor the TOTP clock to real time, not a fixed calendar date
- Select the verification factor server-side from what is currently offered
- Contain an unparsable satisfied_at instead of throwing from the read path
- Hold one-time secrets off the object so var_export cannot disclose them
- --ignore is a path option, so exclude Kernel by path not namespace
- Patch the mutation runner's filter, and kill the 14 real survivors
- Restore database lock wait settings
- Issue and cap authentication challenges
- Recreate pruned throttle windows
- Make outbox rollback portable
- Claim delivery spend reservations atomically
- Make outbox retries and spend release explicit
- Preserve delivery reservation release history
- Classify exhausted queue attempts
- Classify queue failure from provider evidence
- Align delivery report windows
- Prune reservations from recorded outbox state
- Index delivery reservations by window
- Make captcha escalation explicitly opt in
- Fail closed on captcha provider errors
- Preserve captcha configuration errors
- Diagnose unverified identifier population

### Build
- Run mutation testing with Pest instead of Infection
- Remove infection/infection

### Ci
- Run delivery contention race in matrix

### Mutation
- Confirm full factors scope
- Confirm Tier 1 rows at 3e173fe
- Closing Flow and Throttle sweep at 807ce56

### Tools
- Diff mutation classifications by identity

