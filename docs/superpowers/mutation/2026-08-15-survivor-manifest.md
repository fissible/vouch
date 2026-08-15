# Authoritative survivor manifest

Run: `pest --mutate --class="Fissible\Vouch" --ignore="Kernel"` — 2026-08-15, on a
**patched install** (`patches/pest-plugin-mutate-3.0.5-chunk-filters.patch`),
against a clean tree at 719 tests.

```
1314 mutations · 60 files · 60 RUN · 0 kernel · 0 fatals · 0 "No tests found"
225 untested · 21 uncovered · 4 timeout · 1064 tested · 81.28% · 834s
```

**246 rows require a ruling: 225 untested + 21 uncovered.** All 246 are ruled.

The 4 timeouts are unchanged in count and recorded separately as irreducible
non-terminating mutants in `2026-08-13-factors-survivors.md`. This run labels only
`UNTESTED` and `UNCOVERED` rows individually, so their identities are carried
forward from that enumeration rather than re-derived here.

## Closure checks

| Check | Result |
|---|---|
| Run integrity | **PASS** |
| Every emitted group has explicit membership in a ruling | **PASS** |
| No file gained survivors | **PASS** |

**Run integrity.** `Fatal error` count is zero; "1314 Mutations for 60 Files"
matches 60 distinct `RUN` lines, so the run did not truncate; no `src/Kernel/`
row appears, so `--ignore` took effect; and no child reported `No tests found`,
the signature of the filter defect the patch exists to prevent.

**Membership.** A file having an "N of N" document is *necessary but not
sufficient* — sharing a filename with a ruling is not being ruled by it. Each of
the 137 groups was checked against its document's explicit ruled set, and every
document's current count is exact or a subset of its claim:

| Document | Claim | Rows now | |
|---|---|---|---|
| `2026-08-14-exception-rulings` | 46 of 46 | 46 | exact |
| `2026-08-14-integrity-rulings` | 29 of 29 | 29 | exact |
| `2026-08-15-secrets-delivery-rulings` | 12 of 12 | 12 | exact |
| `2026-08-14-audience-rulings` | 34 of 34 | 29 | subset |
| `2026-08-14-driver-rulings` | 79 of 79 | 75 | subset |
| `2026-08-14-provider-rulings` | 62 of 62 | 6 | subset |
| `2026-08-15-no-candidate-rulings` | 44 of 44 | 35 | subset |
| `2026-08-15-candidate-rulings` | 19 of 19 | 13 | subset |
| `2026-08-15-matrix-rulings` | matrix row 4 | 1 | exact |
| | | **246** | **0 unruled, 0 double-claimed** |

**No file gained survivors.** 261 → 246 across 37 files, and no file grew. This is
the separate safeguard that makes a *shrinking* set safe to inherit: an
exhaustive ruling covers the rows that existed when it was written, so a subset
of those is still ruled, but a file that grew would have rows no document saw.

## Two views, deliberately

The **137 groups** are the review unit: one distinct `(file, mutator, expression)`
each. The **246 raw rows** are the tool's evidence. Both are kept so that a future
mutator-version change — which would introduce new groups — stays distinguishable
from duplicate mutations against the same expression, which only add rows.

Rows are referenced by `(file, mutator, expression)`. Line numbers and mutation
IDs both drift: `EnrollmentGuard` moved from line 97 to 111 under a docblock edit,
and its ID changed with it, while the statement stayed identical.

## Review unit — 137 groups

| rows | file | mutator | expression | ruling document |
|---|---|---|---|---|
| 2 | `src/Attempts/ConflictingMutations.php` | ConcatRemoveLeft | `return new self(sprintf('Two single-use mutations both target "%s" in one transition. Ex` | `2026-08-14-exception-rulings` |
| 2 | `src/Attempts/ConflictingMutations.php` | ConcatRemoveRight | `return new self(sprintf('Two single-use mutations both target "%s" in one transition. Ex` | `2026-08-14-exception-rulings` |
| 2 | `src/Attempts/ConflictingMutations.php` | ConcatSwitchSides | `return new self(sprintf('Two single-use mutations both target "%s" in one transition. Ex` | `2026-08-14-exception-rulings` |
| 1 | `src/Attempts/DatabaseAttemptStore.php` | TrueToFalse | `$seen[$target] = true;` | `2026-08-15-no-candidate-rulings` |
| 1 | `src/Attempts/DatabaseAttemptStore.php` | UnwrapArrayValues | `$mutations = array_values($mutations);` | `2026-08-15-no-candidate-rulings` |
| 2 | `src/Attempts/MisdirectedMutation.php` | ConcatRemoveLeft | `return new self(sprintf('ConsumeChallenge for challenge %d named attempt %d, but this tr` | `2026-08-14-exception-rulings` |
| 2 | `src/Attempts/MisdirectedMutation.php` | ConcatRemoveRight | `return new self(sprintf('ConsumeChallenge for challenge %d named attempt %d, but this tr` | `2026-08-14-exception-rulings` |
| 2 | `src/Attempts/MisdirectedMutation.php` | ConcatSwitchSides | `return new self(sprintf('ConsumeChallenge for challenge %d named attempt %d, but this tr` | `2026-08-14-exception-rulings` |
| 1 | `src/Attempts/Mutations/ConsumeChallenge.php` | ConcatSwitchSides | `return 'challenge:' . $this->challengeId;` | `2026-08-15-candidate-rulings` |
| 1 | `src/Attempts/TransitionRefused.php` | ConcatRemoveLeft | `parent::__construct('Transition refused: ' . $outcome->value);` | `2026-08-14-exception-rulings` |
| 1 | `src/Attempts/TransitionRefused.php` | ConcatRemoveRight | `parent::__construct('Transition refused: ' . $outcome->value);` | `2026-08-14-exception-rulings` |
| 1 | `src/Attempts/TransitionRefused.php` | ConcatSwitchSides | `parent::__construct('Transition refused: ' . $outcome->value);` | `2026-08-14-exception-rulings` |
| 1 | `src/Attempts/TransitionRefused.php` | RemoveMethodCall | `parent::__construct('Transition refused: ' . $outcome->value);` | `2026-08-14-exception-rulings` |
| 2 | `src/Attempts/UnknownMutation.php` | ConcatRemoveLeft | `return new self(sprintf('DatabaseAttemptStore cannot execute %s (target "%s"). Every sin` | `2026-08-14-exception-rulings` |
| 2 | `src/Attempts/UnknownMutation.php` | ConcatRemoveRight | `return new self(sprintf('DatabaseAttemptStore cannot execute %s (target "%s"). Every sin` | `2026-08-14-exception-rulings` |
| 2 | `src/Attempts/UnknownMutation.php` | ConcatSwitchSides | `return new self(sprintf('DatabaseAttemptStore cannot execute %s (target "%s"). Every sin` | `2026-08-14-exception-rulings` |
| 1 | `src/Console/VouchPruneCommand.php` | DecrementInteger | `$retentionDays = Config::integer('vouch.sessions.revocation_retention_days', 30);` | `2026-08-15-candidate-rulings` |
| 1 | `src/Console/VouchPruneCommand.php` | IncrementInteger | `$retentionDays = Config::integer('vouch.sessions.revocation_retention_days', 30);` | `2026-08-15-candidate-rulings` |
| 1 | `src/Enrollment/EnrollmentGuard.php` | RemoveMethodCall | `$this->connection->table('auth_enrollment_locks')->where('user_id', $userId)->where('typ` | `2026-08-15-matrix-rulings` |
| 1 | `src/Enrollment/EnrollmentRefused.php` | ConcatRemoveLeft | `return new self(sprintf('Another enrollment for this user\'s %s credential is in progres` | `2026-08-14-exception-rulings` |
| 2 | `src/Enrollment/EnrollmentRefused.php` | ConcatRemoveLeft | `return new self(sprintf('Enrolling this %s credential would leave %d active, but at most` | `2026-08-14-exception-rulings` |
| 1 | `src/Enrollment/EnrollmentRefused.php` | ConcatRemoveRight | `return new self(sprintf('Another enrollment for this user\'s %s credential is in progres` | `2026-08-14-exception-rulings` |
| 2 | `src/Enrollment/EnrollmentRefused.php` | ConcatRemoveRight | `return new self(sprintf('Enrolling this %s credential would leave %d active, but at most` | `2026-08-14-exception-rulings` |
| 1 | `src/Enrollment/EnrollmentRefused.php` | ConcatSwitchSides | `return new self(sprintf('Another enrollment for this user\'s %s credential is in progres` | `2026-08-14-exception-rulings` |
| 2 | `src/Enrollment/EnrollmentRefused.php` | ConcatSwitchSides | `return new self(sprintf('Enrolling this %s credential would leave %d active, but at most` | `2026-08-14-exception-rulings` |
| 1 | `src/Enrollment/EnrollmentRefused.php` | DecrementInteger | `parent::__construct($message, 0, $previous);` | `2026-08-14-exception-rulings` |
| 1 | `src/Enrollment/EnrollmentRefused.php` | IncrementInteger | `parent::__construct($message, 0, $previous);` | `2026-08-14-exception-rulings` |
| 1 | `src/Enrollment/EnrollmentRefused.php` | RemoveMethodCall | `parent::__construct($message, 0, $previous);` | `2026-08-14-exception-rulings` |
| 1 | `src/Factors/Drivers/OtpFactor.php` | ConcatRemoveLeft | `throw new InvalidArgumentException(sprintf('%s delivers to "%s" identifiers, but identif` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/OtpFactor.php` | ConcatRemoveLeft | `throw new InvalidArgumentException(sprintf('ChallengeRequest named no credential and use` | `2026-08-14-driver-rulings` |
| 2 | `src/Factors/Drivers/OtpFactor.php` | ConcatRemoveLeft | `throw new InvalidArgumentException(sprintf('Credential %d is a "%s", but %s issues "%s" ` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/OtpFactor.php` | ConcatRemoveRight | `throw new InvalidArgumentException(sprintf('%s delivers to "%s" identifiers, but identif` | `2026-08-14-driver-rulings` |
| 3 | `src/Factors/Drivers/OtpFactor.php` | ConcatRemoveRight | `throw new InvalidArgumentException(sprintf('%s requires a code length of at least 1: con` | `2026-08-14-driver-rulings` |
| 3 | `src/Factors/Drivers/OtpFactor.php` | ConcatRemoveRight | `throw new InvalidArgumentException(sprintf('%s requires a ttl of at least 1 second: conf` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/OtpFactor.php` | ConcatRemoveRight | `throw new InvalidArgumentException(sprintf('ChallengeRequest named no credential and use` | `2026-08-14-driver-rulings` |
| 2 | `src/Factors/Drivers/OtpFactor.php` | ConcatRemoveRight | `throw new InvalidArgumentException(sprintf('Credential %d is a "%s", but %s issues "%s" ` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/OtpFactor.php` | ConcatSwitchSides | `throw new InvalidArgumentException(sprintf('%s delivers to "%s" identifiers, but identif` | `2026-08-14-driver-rulings` |
| 3 | `src/Factors/Drivers/OtpFactor.php` | ConcatSwitchSides | `throw new InvalidArgumentException(sprintf('%s requires a code length of at least 1: con` | `2026-08-14-driver-rulings` |
| 3 | `src/Factors/Drivers/OtpFactor.php` | ConcatSwitchSides | `throw new InvalidArgumentException(sprintf('%s requires a ttl of at least 1 second: conf` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/OtpFactor.php` | ConcatSwitchSides | `throw new InvalidArgumentException(sprintf('ChallengeRequest named no credential and use` | `2026-08-14-driver-rulings` |
| 2 | `src/Factors/Drivers/OtpFactor.php` | ConcatSwitchSides | `throw new InvalidArgumentException(sprintf('Credential %d is a "%s", but %s issues "%s" ` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/OtpFactor.php` | InstanceOfToTrue | `if (!$sole instanceof AuthCredential) {` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/OtpFactor.php` | RemoveArrayItem | `return AuthCredential::create(['user_id' => $userId, 'type' => $this->id(), 'identifier_` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/OtpFactor.php` | RemoveEarlyReturn | `// GuardsChallengeTarget makes this unreachable for OTP; failing` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/OtpFactor.php` | RemoveStringCast | `$code .= (string) $this->random->int(0, 9);` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/PasswordFactor.php` | RemoveEarlyReturn | `return FactorResult::failed(FactorFailure::NoCredential);` | `2026-08-15-candidate-rulings` |
| 1 | `src/Factors/Drivers/RecoveryCodeFactor.php` | ConcatRemoveLeft | `throw new InvalidArgumentException(sprintf('RecoveryCodeFactor requires a length of at l` | `2026-08-14-driver-rulings` |
| 3 | `src/Factors/Drivers/RecoveryCodeFactor.php` | ConcatRemoveRight | `throw new InvalidArgumentException(sprintf('RecoveryCodeFactor requires a count of at le` | `2026-08-14-driver-rulings` |
| 3 | `src/Factors/Drivers/RecoveryCodeFactor.php` | ConcatRemoveRight | `throw new InvalidArgumentException(sprintf('RecoveryCodeFactor requires a length of at l` | `2026-08-14-driver-rulings` |
| 3 | `src/Factors/Drivers/RecoveryCodeFactor.php` | ConcatSwitchSides | `throw new InvalidArgumentException(sprintf('RecoveryCodeFactor requires a count of at le` | `2026-08-14-driver-rulings` |
| 4 | `src/Factors/Drivers/RecoveryCodeFactor.php` | ConcatSwitchSides | `throw new InvalidArgumentException(sprintf('RecoveryCodeFactor requires a length of at l` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/RecoveryCodeFactor.php` | RemoveEarlyReturn | `return FactorResult::failed(FactorFailure::NoCredential);` | `2026-08-14-driver-rulings` |
| 3 | `src/Factors/Drivers/TotpFactor.php` | ConcatRemoveLeft | `throw new InvalidArgumentException(sprintf('TotpFactor requires a non-negative window: c` | `2026-08-14-driver-rulings` |
| 2 | `src/Factors/Drivers/TotpFactor.php` | ConcatRemoveLeft | `throw new InvalidArgumentException(sprintf('TotpFactor requires a period of at least 1 s` | `2026-08-14-driver-rulings` |
| 2 | `src/Factors/Drivers/TotpFactor.php` | ConcatRemoveLeft | `throw new InvalidArgumentException(sprintf('TotpFactor requires at least 1 digit: config` | `2026-08-14-driver-rulings` |
| 3 | `src/Factors/Drivers/TotpFactor.php` | ConcatRemoveRight | `throw new InvalidArgumentException('TotpFactor requires a non-empty issuer: config "vouc` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/TotpFactor.php` | ConcatRemoveRight | `throw new InvalidArgumentException('TotpFactor::enroll() requires a non-empty "label" st` | `2026-08-14-driver-rulings` |
| 3 | `src/Factors/Drivers/TotpFactor.php` | ConcatRemoveRight | `throw new InvalidArgumentException(sprintf('TotpFactor requires a non-negative window: c` | `2026-08-14-driver-rulings` |
| 2 | `src/Factors/Drivers/TotpFactor.php` | ConcatRemoveRight | `throw new InvalidArgumentException(sprintf('TotpFactor requires a period of at least 1 s` | `2026-08-14-driver-rulings` |
| 2 | `src/Factors/Drivers/TotpFactor.php` | ConcatRemoveRight | `throw new InvalidArgumentException(sprintf('TotpFactor requires at least 1 digit: config` | `2026-08-14-driver-rulings` |
| 3 | `src/Factors/Drivers/TotpFactor.php` | ConcatSwitchSides | `throw new InvalidArgumentException('TotpFactor requires a non-empty issuer: config "vouc` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/TotpFactor.php` | ConcatSwitchSides | `throw new InvalidArgumentException('TotpFactor::enroll() requires a non-empty "label" st` | `2026-08-14-driver-rulings` |
| 3 | `src/Factors/Drivers/TotpFactor.php` | ConcatSwitchSides | `throw new InvalidArgumentException(sprintf('TotpFactor requires a non-negative window: c` | `2026-08-14-driver-rulings` |
| 2 | `src/Factors/Drivers/TotpFactor.php` | ConcatSwitchSides | `throw new InvalidArgumentException(sprintf('TotpFactor requires a period of at least 1 s` | `2026-08-14-driver-rulings` |
| 2 | `src/Factors/Drivers/TotpFactor.php` | ConcatSwitchSides | `throw new InvalidArgumentException(sprintf('TotpFactor requires at least 1 digit: config` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/TotpFactor.php` | ContinueToBreak | `continue;` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/TotpFactor.php` | PlusToMinus | `$step = $currentStep + $offset;` | `2026-08-14-driver-rulings` |
| 1 | `src/Factors/Drivers/TotpFactor.php` | RemoveEarlyReturn | `return FactorResult::failed(FactorFailure::NoCredential);` | `2026-08-14-driver-rulings` |
| 2 | `src/Factors/FactorRegistry.php` | ConcatRemoveRight | `throw new LogicException(sprintf('A factor driver is already registered for "%s" (%s). R` | `2026-08-15-no-candidate-rulings` |
| 2 | `src/Factors/FactorRegistry.php` | ConcatSwitchSides | `throw new LogicException(sprintf('A factor driver is already registered for "%s" (%s). R` | `2026-08-15-no-candidate-rulings` |
| 1 | `src/Factors/FactorResult.php` | UnwrapArrayValues | `return new self($factor, null, array_values($mutations));` | `2026-08-15-candidate-rulings` |
| 1 | `src/Flow/AuthFlow.php` | RemoveArrayItem | `$attempt = AuthAttempt::create(['handle' => bin2hex(random_bytes(32)), 'state' => Attemp` | `2026-08-15-no-candidate-rulings` |
| 1 | `src/Flow/AuthFlow.php` | RemoveEarlyReturn | `return 'password';` | `2026-08-15-no-candidate-rulings` |
| 1 | `src/Flow/AuthFlow.php` | RemoveEarlyReturn | `return [];` | `2026-08-15-no-candidate-rulings` |
| 5 | `src/Flow/ScreenBuilder.php` | ConcatRemoveRight | `throw new LogicException('ScreenBuilder cannot shape Outcome::Locked in Phase 2.3. Error` | `2026-08-14-audience-rulings` |
| 5 | `src/Flow/ScreenBuilder.php` | ConcatSwitchSides | `throw new LogicException('ScreenBuilder cannot shape Outcome::Locked in Phase 2.3. Error` | `2026-08-14-audience-rulings` |
| 1 | `src/Flow/UnknownFlowResult.php` | ConcatRemoveRight | `return new self(sprintf('No handler for FlowResult variant %s. Every variant must be han` | `2026-08-14-exception-rulings` |
| 1 | `src/Flow/UnknownFlowResult.php` | ConcatSwitchSides | `return new self(sprintf('No handler for FlowResult variant %s. Every variant must be han` | `2026-08-14-exception-rulings` |
| 4 | `src/Http/AssuranceComparator.php` | RemoveArrayItem | `private const ORDER = ['aal0', 'aal1', 'aal2', 'aal3'];` | `2026-08-15-no-candidate-rulings` |
| 1 | `src/Http/FlowResultHandler.php` | TrueToFalse | `return match (true) {` | `2026-08-15-candidate-rulings` |
| 1 | `src/Http/FlowResultSerializer.php` | TrueToFalse | `return match (true) {` | `2026-08-15-candidate-rulings` |
| 1 | `src/Http/FlowResultSerializer.php` | UnwrapArrayMap | `'fields' => array_map(static fn(FieldSpec $field): array => ['name' => $field->name, 'ty` | `2026-08-15-candidate-rulings` |
| 1 | `src/Http/IntendedDestination.php` | BooleanOrToBooleanAnd | `if (!is_string($safe) \|\| !str_starts_with($safe, '/')) {` | `2026-08-14-integrity-rulings` |
| 1 | `src/Http/IntendedDestination.php` | BooleanOrToBooleanAnd | `if (!str_starts_with($candidate, '/') \|\| str_starts_with($candidate, '//')) {` | `2026-08-14-integrity-rulings` |
| 1 | `src/Http/IntendedDestination.php` | FalseToTrue | `if ($parts === false) {` | `2026-08-14-integrity-rulings` |
| 1 | `src/Http/IntendedDestination.php` | ForeachEmptyIterable | `foreach (['scheme', 'host', 'port', 'user', 'pass'] as $component) {` | `2026-08-14-integrity-rulings` |
| 5 | `src/Http/IntendedDestination.php` | RemoveArrayItem | `foreach (['scheme', 'host', 'port', 'user', 'pass'] as $component) {` | `2026-08-14-integrity-rulings` |
| 4 | `src/Http/IntendedDestination.php` | RemoveEarlyReturn | `return null;` | `2026-08-14-integrity-rulings` |
| 1 | `src/Http/IntendedDestination.php` | StrStartsWithToStrEndsWith | `if (!str_starts_with($candidate, '/') \|\| str_starts_with($candidate, '//')) {` | `2026-08-14-integrity-rulings` |
| 3 | `src/Http/Middleware/RequireAssurance.php` | ConcatRemoveRight | `throw new RuntimeException('Vouch requires vouch.step_up.presentation_url to be configur` | `2026-08-15-no-candidate-rulings` |
| 3 | `src/Http/Middleware/RequireAssurance.php` | ConcatSwitchSides | `throw new RuntimeException('Vouch requires vouch.step_up.presentation_url to be configur` | `2026-08-15-no-candidate-rulings` |
| 1 | `src/Models/AuthAttempt.php` | RemoveArrayItem | `return ['state' => AttemptState::class, 'version' => 'integer', 'satisfied_factors' => '` | `2026-08-15-candidate-rulings` |
| 1 | `src/Models/AuthChallenge.php` | RemoveArrayItem | `return ['attempts' => 'integer', 'expires_at' => 'datetime', 'consumed_at' => 'datetime'` | `2026-08-15-candidate-rulings` |
| 1 | `src/Models/AuthConnection.php` | RemoveArrayItem | `protected $hidden = ['client_secret'];` | `2026-08-15-candidate-rulings` |
| 1 | `src/Models/AuthCredential.php` | RemoveArrayItem | `protected $hidden = ['secret'];` | `2026-08-15-candidate-rulings` |
| 1 | `src/Models/AuthCredential.php` | RemoveArrayItem | `return ['secret' => 'encrypted', 'is_multi_factor' => 'boolean', 'user_verified' => 'boo` | `2026-08-15-candidate-rulings` |
| 3 | `src/Notifications/UnconfiguredOtpDelivery.php` | ConcatRemoveRight | `throw new RuntimeException('No OTP delivery is configured. Bind Fissible\Vouch\Contracts` | `2026-08-15-secrets-delivery-rulings` |
| 3 | `src/Notifications/UnconfiguredOtpDelivery.php` | ConcatSwitchSides | `throw new RuntimeException('No OTP delivery is configured. Bind Fissible\Vouch\Contracts` | `2026-08-15-secrets-delivery-rulings` |
| 2 | `src/Persistence/ChallengeTargetViolation.php` | ConcatRemoveRight | `return new self(sprintf('A %s challenge must name the credential it was delivered agains` | `2026-08-14-integrity-rulings` |
| 1 | `src/Persistence/ChallengeTargetViolation.php` | ConcatRemoveRight | `return new self(sprintf('Credential %d does not belong to the attempt user (%s). A chall` | `2026-08-14-integrity-rulings` |
| 2 | `src/Persistence/ChallengeTargetViolation.php` | ConcatSwitchSides | `return new self(sprintf('A %s challenge must name the credential it was delivered agains` | `2026-08-14-integrity-rulings` |
| 1 | `src/Persistence/ChallengeTargetViolation.php` | ConcatSwitchSides | `return new self(sprintf('Credential %d does not belong to the attempt user (%s). A chall` | `2026-08-14-integrity-rulings` |
| 1 | `src/Persistence/ChallengeTargetViolation.php` | RemoveStringCast | `return new self(sprintf('Credential %d does not belong to the attempt user (%s). A chall` | `2026-08-14-integrity-rulings` |
| 2 | `src/Persistence/IdentifierLinkageViolation.php` | ConcatRemoveLeft | `return new self(sprintf('Identifier %d is not verified. An unverified identifier is atta` | `2026-08-14-audience-rulings` |
| 3 | `src/Persistence/IdentifierLinkageViolation.php` | ConcatRemoveLeft | `return new self(sprintf('Identifier %d is referenced by at least one credential, so its ` | `2026-08-14-audience-rulings` |
| 2 | `src/Persistence/IdentifierLinkageViolation.php` | ConcatRemoveRight | `return new self(sprintf('Identifier %d is not verified. An unverified identifier is atta` | `2026-08-14-audience-rulings` |
| 3 | `src/Persistence/IdentifierLinkageViolation.php` | ConcatRemoveRight | `return new self(sprintf('Identifier %d is referenced by at least one credential, so its ` | `2026-08-14-audience-rulings` |
| 2 | `src/Persistence/IdentifierLinkageViolation.php` | ConcatRemoveRight | `return new self(sprintf('Refusing to link a credential owned by user %d to an identifier` | `2026-08-14-audience-rulings` |
| 2 | `src/Persistence/IdentifierLinkageViolation.php` | ConcatSwitchSides | `return new self(sprintf('Identifier %d is not verified. An unverified identifier is atta` | `2026-08-14-audience-rulings` |
| 3 | `src/Persistence/IdentifierLinkageViolation.php` | ConcatSwitchSides | `return new self(sprintf('Identifier %d is referenced by at least one credential, so its ` | `2026-08-14-audience-rulings` |
| 2 | `src/Persistence/IdentifierLinkageViolation.php` | ConcatSwitchSides | `return new self(sprintf('Refusing to link a credential owned by user %d to an identifier` | `2026-08-14-audience-rulings` |
| 1 | `src/Persistence/ValueBoundViolation.php` | ConcatRemoveRight | `return new self(sprintf('%s::$%s exceeds its %d-character bound (%d given). Vouch refuse` | `2026-08-14-exception-rulings` |
| 1 | `src/Persistence/ValueBoundViolation.php` | ConcatRemoveRight | `return new self(sprintf('%s::$%s must be ASCII. Vouch refuses rather than normalises: tw` | `2026-08-14-exception-rulings` |
| 1 | `src/Persistence/ValueBoundViolation.php` | ConcatSwitchSides | `return new self(sprintf('%s::$%s exceeds its %d-character bound (%d given). Vouch refuse` | `2026-08-14-exception-rulings` |
| 1 | `src/Persistence/ValueBoundViolation.php` | ConcatSwitchSides | `return new self(sprintf('%s::$%s must be ASCII. Vouch refuses rather than normalises: tw` | `2026-08-14-exception-rulings` |
| 1 | `src/Secrets/OneTimeSecret.php` | ConcatRemoveLeft | `throw new LogicException('A OneTimeSecret cannot be cloned: the value belongs to one ins` | `2026-08-15-secrets-delivery-rulings` |
| 1 | `src/Secrets/OneTimeSecret.php` | ConcatRemoveLeft | `throw new LogicException('A OneTimeSecret cannot be rebuilt from var_export() output: th` | `2026-08-15-secrets-delivery-rulings` |
| 1 | `src/Secrets/OneTimeSecret.php` | ConcatRemoveRight | `throw new LogicException('A OneTimeSecret cannot be cloned: the value belongs to one ins` | `2026-08-15-secrets-delivery-rulings` |
| 1 | `src/Secrets/OneTimeSecret.php` | ConcatRemoveRight | `throw new LogicException('A OneTimeSecret cannot be rebuilt from var_export() output: th` | `2026-08-15-secrets-delivery-rulings` |
| 1 | `src/Secrets/OneTimeSecret.php` | ConcatSwitchSides | `throw new LogicException('A OneTimeSecret cannot be cloned: the value belongs to one ins` | `2026-08-15-secrets-delivery-rulings` |
| 1 | `src/Secrets/OneTimeSecret.php` | ConcatSwitchSides | `throw new LogicException('A OneTimeSecret cannot be rebuilt from var_export() output: th` | `2026-08-15-secrets-delivery-rulings` |
| 2 | `src/Secrets/SecretAlreadyRevealed.php` | ConcatRemoveLeft | `return new self('This secret has already been revealed and cannot be read again. ' . 'En` | `2026-08-14-exception-rulings` |
| 2 | `src/Secrets/SecretAlreadyRevealed.php` | ConcatRemoveRight | `return new self('This secret has already been revealed and cannot be read again. ' . 'En` | `2026-08-14-exception-rulings` |
| 2 | `src/Secrets/SecretAlreadyRevealed.php` | ConcatSwitchSides | `return new self('This secret has already been revealed and cannot be read again. ' . 'En` | `2026-08-14-exception-rulings` |
| 2 | `src/Sessions/SessionRotationFailed.php` | ConcatRemoveLeft | `return new self('Vouch could not record the rotated session. The regenerated host sessio` | `2026-08-14-integrity-rulings` |
| 2 | `src/Sessions/SessionRotationFailed.php` | ConcatRemoveRight | `return new self('Vouch could not record the rotated session. The regenerated host sessio` | `2026-08-14-integrity-rulings` |
| 2 | `src/Sessions/SessionRotationFailed.php` | ConcatSwitchSides | `return new self('Vouch could not record the rotated session. The regenerated host sessio` | `2026-08-14-integrity-rulings` |
| 1 | `src/Sessions/SessionRotationFailed.php` | DecrementInteger | `return new self('Vouch could not record the rotated session. The regenerated host sessio` | `2026-08-14-integrity-rulings` |
| 1 | `src/Sessions/SessionRotationFailed.php` | IncrementInteger | `return new self('Vouch could not record the rotated session. The regenerated host sessio` | `2026-08-14-integrity-rulings` |
| 1 | `src/Support/DatabaseTime.php` | ConcatRemoveLeft | `default => throw new InvalidArgumentException('Vouch cannot express a database-clock dea` | `2026-08-15-no-candidate-rulings` |
| 4 | `src/Support/DatabaseTime.php` | ConcatRemoveRight | `default => throw new InvalidArgumentException('Vouch cannot express a database-clock dea` | `2026-08-15-no-candidate-rulings` |
| 5 | `src/Support/DatabaseTime.php` | ConcatSwitchSides | `default => throw new InvalidArgumentException('Vouch cannot express a database-clock dea` | `2026-08-15-no-candidate-rulings` |
| 3 | `src/Vouch.php` | ConcatRemoveRight | `throw new RuntimeException('Vouch::stepUp(' . $level . ') requires vouch.step_up.present` | `2026-08-15-no-candidate-rulings` |
| 3 | `src/Vouch.php` | ConcatSwitchSides | `throw new RuntimeException('Vouch::stepUp(' . $level . ') requires vouch.step_up.present` | `2026-08-15-no-candidate-rulings` |
| 2 | `src/VouchServiceProvider.php` | ConcatRemoveLeft | `throw new \RuntimeException('Vouch requires ValidatesVouchSession in the "web" middlewar` | `2026-08-14-provider-rulings` |
| 2 | `src/VouchServiceProvider.php` | ConcatRemoveRight | `throw new \RuntimeException('Vouch requires ValidatesVouchSession in the "web" middlewar` | `2026-08-14-provider-rulings` |
| 2 | `src/VouchServiceProvider.php` | ConcatSwitchSides | `throw new \RuntimeException('Vouch requires ValidatesVouchSession in the "web" middlewar` | `2026-08-14-provider-rulings` |

## Tool evidence — 246 raw rows

| result | file | line | mutator | id | ruling document |
|---|---|---|---|---|---|
| UNTESTED | src/Attempts/ConflictingMutations.php | 21 | ConcatRemoveLeft | 36abde7c32d49221 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/ConflictingMutations.php | 21 | ConcatRemoveLeft | c34497f6998e54bf | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/ConflictingMutations.php | 21 | ConcatRemoveRight | 89dc80a8d7d42723 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/ConflictingMutations.php | 21 | ConcatRemoveRight | b1e4740ced34d588 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/ConflictingMutations.php | 21 | ConcatSwitchSides | aeb968d362e332c9 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/ConflictingMutations.php | 21 | ConcatSwitchSides | 462475de27a05f16 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/DatabaseAttemptStore.php | 37 | UnwrapArrayValues | 67393e4199909dac | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Attempts/DatabaseAttemptStore.php | 113 | TrueToFalse | 314cd628bbef6df1 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Attempts/MisdirectedMutation.php | 26 | ConcatRemoveLeft | ca89e653f3e58dea | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/MisdirectedMutation.php | 26 | ConcatRemoveLeft | 3372bc225d60a5f3 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/MisdirectedMutation.php | 26 | ConcatRemoveRight | 71b5949f2b8b1ce5 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/MisdirectedMutation.php | 26 | ConcatRemoveRight | 921eee43c7424cdd | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/MisdirectedMutation.php | 26 | ConcatSwitchSides | 8b01aceb557545ea | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/MisdirectedMutation.php | 26 | ConcatSwitchSides | 84cf6249639d4048 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/Mutations/ConsumeChallenge.php | 26 | ConcatSwitchSides | 9866712dc36924f5 | `2026-08-15-candidate-rulings` |
| UNTESTED | src/Attempts/TransitionRefused.php | 25 | ConcatRemoveLeft | 7fa8a31e61d67c59 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/TransitionRefused.php | 25 | ConcatRemoveRight | db3c6704af816935 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/TransitionRefused.php | 25 | ConcatSwitchSides | 8a7d26002751a030 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/TransitionRefused.php | 25 | RemoveMethodCall | c2e993f75ccb8281 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/UnknownMutation.php | 24 | ConcatRemoveLeft | 3cc5835b420bad2f | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/UnknownMutation.php | 24 | ConcatRemoveLeft | b7b2b4985b73c305 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/UnknownMutation.php | 24 | ConcatRemoveRight | 2644d9dfbf572757 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/UnknownMutation.php | 24 | ConcatRemoveRight | ec82ab1c56f81423 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/UnknownMutation.php | 24 | ConcatSwitchSides | e0637cc4c4e5772d | `2026-08-14-exception-rulings` |
| UNTESTED | src/Attempts/UnknownMutation.php | 24 | ConcatSwitchSides | 8ebdf679df427913 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Console/VouchPruneCommand.php | 41 | DecrementInteger | 916ce1a5cd2fefe4 | `2026-08-15-candidate-rulings` |
| UNTESTED | src/Console/VouchPruneCommand.php | 41 | IncrementInteger | 7245e96a1f5b7ff6 | `2026-08-15-candidate-rulings` |
| UNTESTED | src/Enrollment/EnrollmentGuard.php | 111 | RemoveMethodCall | b771d0690d7ae185 | `2026-08-15-matrix-rulings` |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 25 | DecrementInteger | 292cd184bf37a560 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 25 | IncrementInteger | 65d3477af7df5e68 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 25 | RemoveMethodCall | bf723229c4433210 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 32 | ConcatRemoveLeft | 15f20773d121ae66 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 32 | ConcatRemoveLeft | 3d6be94c0a120cf0 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 32 | ConcatRemoveRight | aef5a8d9faf53cc8 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 32 | ConcatRemoveRight | b9de9bb73a932798 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 32 | ConcatSwitchSides | 8a49b5a2700578c5 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 32 | ConcatSwitchSides | 242ea18cc9074d8e | `2026-08-14-exception-rulings` |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 47 | ConcatRemoveLeft | 8c23b95089241a67 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 47 | ConcatRemoveRight | d2183157768a96dc | `2026-08-14-exception-rulings` |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 47 | ConcatSwitchSides | db4785940dcb4538 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 64 | ConcatRemoveRight | a586166ec7aa35ee | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 64 | ConcatRemoveRight | f27d4a5134d60ae4 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 64 | ConcatRemoveRight | 137ff9d216cbcc7c | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 64 | ConcatSwitchSides | aa22ea1c9d9b0a8f | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 64 | ConcatSwitchSides | 166a7bea83f97e7f | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 64 | ConcatSwitchSides | fe87b4f4e3544399 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 75 | ConcatRemoveRight | 87f3f3fe316e42fc | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 75 | ConcatRemoveRight | cbca3eed699b0f6c | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 75 | ConcatRemoveRight | 2550a7f5b0df821f | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 75 | ConcatSwitchSides | 5ea2feb7bd52b35b | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 75 | ConcatSwitchSides | d17a08522d39e658 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 75 | ConcatSwitchSides | b8404fbd1f3392c8 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 141 | ConcatRemoveLeft | c1cca452cbdd4d7f | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 141 | ConcatRemoveRight | f3d09fa710e82bbe | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 141 | ConcatSwitchSides | 2e7ca47426cf2603 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 178 | RemoveArrayItem | fbb181a5240dc59e | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 204 | ConcatRemoveLeft | 34bf7ec9b32b1427 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 204 | ConcatRemoveLeft | 60fd12dd70ef3337 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 204 | ConcatRemoveRight | 99d2094898af4fa8 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 204 | ConcatRemoveRight | 2896e004ab17321b | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 204 | ConcatSwitchSides | 8080096e50809869 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 204 | ConcatSwitchSides | 5edfe6edecc86197 | `2026-08-14-driver-rulings` |
| UNCOVERED | src/Factors/Drivers/OtpFactor.php | 299 | RemoveEarlyReturn | 0f177138949fd14c | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 381 | ConcatRemoveLeft | b273ea43c63c0f3d | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 381 | ConcatRemoveRight | 1d5f9ae99b4b0c8a | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 381 | ConcatSwitchSides | 2a1d28c1bc225a59 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 391 | InstanceOfToTrue | 5d7ccc8a0c27a163 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 421 | RemoveStringCast | 9a41b956dfc44c30 | `2026-08-14-driver-rulings` |
| UNCOVERED | src/Factors/Drivers/PasswordFactor.php | 133 | RemoveEarlyReturn | 7d7de55a3d58ff0b | `2026-08-15-candidate-rulings` |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 68 | ConcatRemoveRight | 7c746651267a3159 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 68 | ConcatRemoveRight | f09256e980ef6d65 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 68 | ConcatRemoveRight | 4809ca9c8573efa3 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 68 | ConcatSwitchSides | 895a8934653c1c47 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 68 | ConcatSwitchSides | a454ba44ed7c0944 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 68 | ConcatSwitchSides | 4d24842a75a5d958 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatRemoveLeft | bd55c7d82eb25b8a | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatRemoveRight | 9fcf8c2919bbcb1a | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatRemoveRight | 2c41e0e48cf4cf55 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatRemoveRight | 147ac020631b09d5 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatSwitchSides | 1891faf13188f29b | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatSwitchSides | 6e4c331fb00f9404 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatSwitchSides | 8dd6276f865fdca4 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatSwitchSides | 93dadcd15ac3dfdc | `2026-08-14-driver-rulings` |
| UNCOVERED | src/Factors/Drivers/RecoveryCodeFactor.php | 190 | RemoveEarlyReturn | 13797df0aef85f47 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 63 | ConcatRemoveRight | 016656d9d4b56c25 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 63 | ConcatRemoveRight | 3fd10d48537bb875 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 63 | ConcatRemoveRight | 7bdd9ced1b515510 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 63 | ConcatSwitchSides | 75b88af5f33b7929 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 63 | ConcatSwitchSides | 2cb230be3c50abe7 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 63 | ConcatSwitchSides | 2762b74ecba21f86 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 72 | ConcatRemoveLeft | d74dba56d718ad79 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 72 | ConcatRemoveLeft | 30cb23da82d1355a | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 72 | ConcatRemoveRight | 4397a41cf57c97f5 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 72 | ConcatRemoveRight | 4da1d309cbce6fb7 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 72 | ConcatSwitchSides | f7a2f85ce2b9c816 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 72 | ConcatSwitchSides | 3bd3d7d6302fb67b | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 81 | ConcatRemoveLeft | 7c9e86e98e5a84fd | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 81 | ConcatRemoveLeft | 2acb2724fbe7709d | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 81 | ConcatRemoveRight | bc18eadfafe1aa33 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 81 | ConcatRemoveRight | f3f576c9b258555e | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 81 | ConcatSwitchSides | 79adfd880f221168 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 81 | ConcatSwitchSides | a76458921cc2e2a1 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatRemoveLeft | 503a8cb67369b78a | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatRemoveLeft | a03fba4b89ad34f7 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatRemoveLeft | 0b410f7ff99198cd | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatRemoveRight | 613d6cf338a9fca9 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatRemoveRight | 0340bf2fb9c84f06 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatRemoveRight | fec3bceb991c1509 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatSwitchSides | ca6ef09ce2f8410a | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatSwitchSides | b644e3bfe56cd9a4 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatSwitchSides | 372f53a7c6ab0a25 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 128 | ConcatRemoveRight | d43c621945d47b04 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 128 | ConcatSwitchSides | a3fbf3b0342d2605 | `2026-08-14-driver-rulings` |
| UNCOVERED | src/Factors/Drivers/TotpFactor.php | 192 | RemoveEarlyReturn | b33b87c3674172db | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 280 | PlusToMinus | 825c19b291566c65 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 283 | ContinueToBreak | 72bc7b20776598b8 | `2026-08-14-driver-rulings` |
| UNTESTED | src/Factors/FactorRegistry.php | 29 | ConcatRemoveRight | df9acb2e87b685c2 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Factors/FactorRegistry.php | 29 | ConcatRemoveRight | ac11b4c0366d8dd3 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Factors/FactorRegistry.php | 29 | ConcatSwitchSides | 96966b6b4ca66eee | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Factors/FactorRegistry.php | 29 | ConcatSwitchSides | 4c715965861175c0 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Factors/FactorResult.php | 33 | UnwrapArrayValues | 42154a8f487b4873 | `2026-08-15-candidate-rulings` |
| UNTESTED | src/Flow/AuthFlow.php | 101 | RemoveArrayItem | 1d0d951f18ad6bac | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Flow/AuthFlow.php | 329 | RemoveEarlyReturn | 577ee9ed917d58b0 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Flow/AuthFlow.php | 387 | RemoveEarlyReturn | 7b0b64cb43172bbb | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatRemoveRight | cff180f4ea435beb | `2026-08-14-audience-rulings` |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatRemoveRight | a01bc7a39a971015 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatRemoveRight | efc9338329236e05 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatRemoveRight | e2d4a6857728d291 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatRemoveRight | 3f18bbcc85abb33a | `2026-08-14-audience-rulings` |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatSwitchSides | 243333062c202ef8 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatSwitchSides | 32193b2cdd0f4b35 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatSwitchSides | 3df6ef22682a2915 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatSwitchSides | bb98de7a956f458e | `2026-08-14-audience-rulings` |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatSwitchSides | e651d8597a64d858 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Flow/UnknownFlowResult.php | 23 | ConcatRemoveRight | a9f247272595d581 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Flow/UnknownFlowResult.php | 23 | ConcatSwitchSides | a4f60546e4f0f817 | `2026-08-14-exception-rulings` |
| UNCOVERED | src/Http/AssuranceComparator.php | 24 | RemoveArrayItem | 98dc782578dcb775 | `2026-08-15-no-candidate-rulings` |
| UNCOVERED | src/Http/AssuranceComparator.php | 24 | RemoveArrayItem | 9e86faf69f6b7f29 | `2026-08-15-no-candidate-rulings` |
| UNCOVERED | src/Http/AssuranceComparator.php | 24 | RemoveArrayItem | 79f1ecf6f962d77a | `2026-08-15-no-candidate-rulings` |
| UNCOVERED | src/Http/AssuranceComparator.php | 24 | RemoveArrayItem | 5f55f93fd16860d4 | `2026-08-15-no-candidate-rulings` |
| UNCOVERED | src/Http/FlowResultHandler.php | 40 | TrueToFalse | f05b5809fd295180 | `2026-08-15-candidate-rulings` |
| UNCOVERED | src/Http/FlowResultSerializer.php | 34 | TrueToFalse | 263d34d11d6a1685 | `2026-08-15-candidate-rulings` |
| UNTESTED | src/Http/FlowResultSerializer.php | 70 | UnwrapArrayMap | ac94c754135d6fe0 | `2026-08-15-candidate-rulings` |
| UNTESTED | src/Http/IntendedDestination.php | 76 | BooleanOrToBooleanAnd | 5240669a6894d8ef | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Http/IntendedDestination.php | 76 | StrStartsWithToStrEndsWith | 12ff5467cc00c7b4 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Http/IntendedDestination.php | 77 | RemoveEarlyReturn | 5dafcd2bce6202f8 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Http/IntendedDestination.php | 82 | FalseToTrue | 05ab7e9abb839287 | `2026-08-14-integrity-rulings` |
| UNCOVERED | src/Http/IntendedDestination.php | 83 | RemoveEarlyReturn | b5703b5474892050 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Http/IntendedDestination.php | 87 | ForeachEmptyIterable | f4d5c20087a9d032 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Http/IntendedDestination.php | 87 | RemoveArrayItem | 895ed1d8a81d6b25 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Http/IntendedDestination.php | 87 | RemoveArrayItem | 99ebca0c4d42f11b | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Http/IntendedDestination.php | 87 | RemoveArrayItem | 3396aa68f34ac230 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Http/IntendedDestination.php | 87 | RemoveArrayItem | 113d048b229bb648 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Http/IntendedDestination.php | 87 | RemoveArrayItem | 3e0ed98e18e36034 | `2026-08-14-integrity-rulings` |
| UNCOVERED | src/Http/IntendedDestination.php | 89 | RemoveEarlyReturn | ecc9727c2eb89117 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Http/IntendedDestination.php | 95 | BooleanOrToBooleanAnd | dfad39a51184ea74 | `2026-08-14-integrity-rulings` |
| UNCOVERED | src/Http/IntendedDestination.php | 96 | RemoveEarlyReturn | a328e9134f2d69da | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Http/Middleware/RequireAssurance.php | 51 | ConcatRemoveRight | c78968562c7929e0 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Http/Middleware/RequireAssurance.php | 51 | ConcatRemoveRight | 119fc08faaae9e69 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Http/Middleware/RequireAssurance.php | 51 | ConcatRemoveRight | 7d0cf2a71995c867 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Http/Middleware/RequireAssurance.php | 51 | ConcatSwitchSides | 53b0ea8ef5cc0989 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Http/Middleware/RequireAssurance.php | 51 | ConcatSwitchSides | 62d088bb00f91aa3 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Http/Middleware/RequireAssurance.php | 51 | ConcatSwitchSides | bb1f29f5659446e1 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Models/AuthAttempt.php | 42 | RemoveArrayItem | 76e9c7df97f78ca1 | `2026-08-15-candidate-rulings` |
| UNTESTED | src/Models/AuthChallenge.php | 39 | RemoveArrayItem | 66f78eb39e411bcd | `2026-08-15-candidate-rulings` |
| UNCOVERED | src/Models/AuthConnection.php | 34 | RemoveArrayItem | 6119ed96b64ca157 | `2026-08-15-candidate-rulings` |
| UNCOVERED | src/Models/AuthCredential.php | 44 | RemoveArrayItem | 4b830fff1cbb9221 | `2026-08-15-candidate-rulings` |
| UNTESTED | src/Models/AuthCredential.php | 57 | RemoveArrayItem | 91733c3c295cd58c | `2026-08-15-candidate-rulings` |
| UNTESTED | src/Notifications/UnconfiguredOtpDelivery.php | 25 | ConcatRemoveRight | 99de84ef57acce4c | `2026-08-15-secrets-delivery-rulings` |
| UNTESTED | src/Notifications/UnconfiguredOtpDelivery.php | 25 | ConcatRemoveRight | a856c15d50459e58 | `2026-08-15-secrets-delivery-rulings` |
| UNTESTED | src/Notifications/UnconfiguredOtpDelivery.php | 25 | ConcatRemoveRight | 6ab01e3d670173b7 | `2026-08-15-secrets-delivery-rulings` |
| UNTESTED | src/Notifications/UnconfiguredOtpDelivery.php | 25 | ConcatSwitchSides | e0047d7779d8afa2 | `2026-08-15-secrets-delivery-rulings` |
| UNTESTED | src/Notifications/UnconfiguredOtpDelivery.php | 25 | ConcatSwitchSides | 534539ab779f7901 | `2026-08-15-secrets-delivery-rulings` |
| UNTESTED | src/Notifications/UnconfiguredOtpDelivery.php | 25 | ConcatSwitchSides | d609fd3a94bc5ac8 | `2026-08-15-secrets-delivery-rulings` |
| UNTESTED | src/Persistence/ChallengeTargetViolation.php | 21 | ConcatRemoveRight | 433d7c1114fb50e7 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Persistence/ChallengeTargetViolation.php | 21 | ConcatRemoveRight | 7d5e01aa4793d789 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Persistence/ChallengeTargetViolation.php | 21 | ConcatSwitchSides | 5ca775a6b745762a | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Persistence/ChallengeTargetViolation.php | 21 | ConcatSwitchSides | dc21244cae038646 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Persistence/ChallengeTargetViolation.php | 44 | ConcatRemoveRight | 3608d9b285aa439b | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Persistence/ChallengeTargetViolation.php | 44 | ConcatSwitchSides | 371af03870d6250a | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Persistence/ChallengeTargetViolation.php | 47 | RemoveStringCast | 06991a3a633a6884 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 29 | ConcatRemoveRight | d1ade2fbb1793e84 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 29 | ConcatRemoveRight | 5e4463fc3d8d95f5 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 29 | ConcatSwitchSides | c699efe37a3ed883 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 29 | ConcatSwitchSides | 41d754960b368403 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 40 | ConcatRemoveLeft | 91a79912aad87b14 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 40 | ConcatRemoveLeft | 67fc8dc3af2236bd | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 40 | ConcatRemoveRight | b2b692f68f889738 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 40 | ConcatRemoveRight | 0a3921464197b889 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 40 | ConcatSwitchSides | d34cf1f6cf7dad5f | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 40 | ConcatSwitchSides | 5c00e37c4b754904 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatRemoveLeft | cbeead125270e74d | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatRemoveLeft | 3f42da2a4779628d | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatRemoveLeft | cfe2101f1d4424b0 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatRemoveRight | 77c44bc855d9c667 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatRemoveRight | b4dcf2cc1ee8a72b | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatRemoveRight | 7fcc1f79c06c819d | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatSwitchSides | 5bd6d589f667e224 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatSwitchSides | 964ebac2b70cfb9c | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatSwitchSides | aa465f4c91d91a32 | `2026-08-14-audience-rulings` |
| UNTESTED | src/Persistence/ValueBoundViolation.php | 25 | ConcatRemoveRight | 684c32b46bf4002d | `2026-08-14-exception-rulings` |
| UNTESTED | src/Persistence/ValueBoundViolation.php | 25 | ConcatSwitchSides | ce7994fbc88de0c1 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Persistence/ValueBoundViolation.php | 37 | ConcatRemoveRight | a24a48ef184a80c2 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Persistence/ValueBoundViolation.php | 37 | ConcatSwitchSides | 681a0a0946c0ed52 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Secrets/OneTimeSecret.php | 120 | ConcatRemoveLeft | 1ed497e547af8e77 | `2026-08-15-secrets-delivery-rulings` |
| UNTESTED | src/Secrets/OneTimeSecret.php | 120 | ConcatRemoveRight | 026cf6eb81bf1bb1 | `2026-08-15-secrets-delivery-rulings` |
| UNTESTED | src/Secrets/OneTimeSecret.php | 120 | ConcatSwitchSides | ae220c6000cf23c9 | `2026-08-15-secrets-delivery-rulings` |
| UNTESTED | src/Secrets/OneTimeSecret.php | 136 | ConcatRemoveLeft | b1c82f4775ef3de1 | `2026-08-15-secrets-delivery-rulings` |
| UNTESTED | src/Secrets/OneTimeSecret.php | 136 | ConcatRemoveRight | af32c0068ee57565 | `2026-08-15-secrets-delivery-rulings` |
| UNTESTED | src/Secrets/OneTimeSecret.php | 136 | ConcatSwitchSides | ceb2a09ed82d3b85 | `2026-08-15-secrets-delivery-rulings` |
| UNTESTED | src/Secrets/SecretAlreadyRevealed.php | 22 | ConcatRemoveLeft | 5ecf038eb4197d8d | `2026-08-14-exception-rulings` |
| UNTESTED | src/Secrets/SecretAlreadyRevealed.php | 22 | ConcatRemoveLeft | cd472705a5d4de77 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Secrets/SecretAlreadyRevealed.php | 22 | ConcatRemoveRight | eba74c53baa89613 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Secrets/SecretAlreadyRevealed.php | 22 | ConcatRemoveRight | 7c45f9030acd381d | `2026-08-14-exception-rulings` |
| UNTESTED | src/Secrets/SecretAlreadyRevealed.php | 22 | ConcatSwitchSides | 4523064c59aa5fa8 | `2026-08-14-exception-rulings` |
| UNTESTED | src/Secrets/SecretAlreadyRevealed.php | 22 | ConcatSwitchSides | 2777cd01215981bb | `2026-08-14-exception-rulings` |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 24 | ConcatRemoveLeft | 1e1909990d210867 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 24 | ConcatRemoveLeft | b5c9658042c66e43 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 24 | ConcatRemoveRight | 2925bbcfcb243ee3 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 24 | ConcatRemoveRight | 663108f87d7850be | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 24 | ConcatSwitchSides | bfe9e31ee08a6c95 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 24 | ConcatSwitchSides | 0542b3c62c814a93 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 27 | DecrementInteger | dd995c1e9fbbec82 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 27 | IncrementInteger | caf7632c28b9b279 | `2026-08-14-integrity-rulings` |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveLeft | e1f603212532d7fc | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveRight | f3f72400856d8a86 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveRight | 61ba222f84be529e | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveRight | f7a7da5a280c3508 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveRight | a7cf8fb506896371 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatSwitchSides | 5c721da7aa9441d1 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatSwitchSides | 190d2b0a6d9c1658 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatSwitchSides | c4087ff441880b24 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatSwitchSides | 5c2dd311304882a4 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatSwitchSides | 2711db478949107e | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Vouch.php | 42 | ConcatRemoveRight | 70158b81a740db68 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Vouch.php | 42 | ConcatRemoveRight | 29e08b8edee83c54 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Vouch.php | 42 | ConcatRemoveRight | e46ec93dd17342bd | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Vouch.php | 42 | ConcatSwitchSides | 0d74f9f9b8392b8c | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Vouch.php | 42 | ConcatSwitchSides | 92603e91ccaa3a97 | `2026-08-15-no-candidate-rulings` |
| UNTESTED | src/Vouch.php | 42 | ConcatSwitchSides | bed924ecd1f40a82 | `2026-08-15-no-candidate-rulings` |
| UNCOVERED | src/VouchServiceProvider.php | 246 | ConcatRemoveLeft | 9411bf339acdc9a5 | `2026-08-14-provider-rulings` |
| UNCOVERED | src/VouchServiceProvider.php | 246 | ConcatRemoveLeft | ac7b717c78e615aa | `2026-08-14-provider-rulings` |
| UNCOVERED | src/VouchServiceProvider.php | 246 | ConcatRemoveRight | 414cbf21a1c8b8fc | `2026-08-14-provider-rulings` |
| UNCOVERED | src/VouchServiceProvider.php | 246 | ConcatRemoveRight | 27fcaeaa1544a931 | `2026-08-14-provider-rulings` |
| UNCOVERED | src/VouchServiceProvider.php | 246 | ConcatSwitchSides | ca8cd6e1f3538158 | `2026-08-14-provider-rulings` |
| UNCOVERED | src/VouchServiceProvider.php | 246 | ConcatSwitchSides | f0d91d34137b668a | `2026-08-14-provider-rulings` |
