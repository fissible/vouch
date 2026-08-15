# Authoritative survivor manifest — regenerated

Run: `pest --mutate --class="Fissible\Vouch" --ignore="Kernel"` — 2026-08-15,
on a **patched install** (`patches/pest-plugin-mutate-3.0.5-chunk-filters.patch`).

```
1314 mutations · 60 files · 60 RUN · 0 kernel · 0 fatals · 0 "No tests found"
239 untested · 22 uncovered · 4 timeout · 1049 tested · 80.14% · 899s
```

Integrity, checked rather than assumed: the `Fatal error` count is zero, and
"1314 Mutations for 60 Files" matches 60 distinct `RUN` lines, so the run did not
truncate. No child reported `No tests found` — the signature of the filter defect
this run exists to have fixed.

**261 rows require a one-to-one ruling: 239 untested + 22 uncovered.**

The 4 timeouts are unchanged in count and recorded separately as irreducible
non-terminating mutants in `2026-08-13-factors-survivors.md`. This run labels only
`UNTESTED` and `UNCOVERED` rows individually — timeouts appear in the summary
counts only — so their identities are carried forward from that enumeration
rather than re-derived here.

## Closure checks

| Check | Result |
|---|---|
| Patched provider rows report Tested | **PASS** |
| No unruled IDs introduced | **PASS** |
| Only already-resolved / dispositioned classes remain | **NOT CONFIRMED — 63 rows** |

**Check 1 — PASS.** `VouchServiceProvider` reports **0 untested**. The 6 rows
remaining are line 246's exception message, uncovered and ruled prose. Down from
62 surviving rows.

**Check 3 — PASS.** No new mutation escaped. IDs are position sensitive, so one
row appeared "new" at ID level: `EnrollmentGuard` moved from line 97
(`e9cbd881d1bbafc8`) to line 111 (`b771d0690d7ae185`) because a docblock
correction added a net 14 lines, and both lines hold the identical statement.
Verified position-independently instead: **no file gained survivors, and every
surviving (file, mutator) pair existed in the prior manifest.**

**Check 2 — NOT CONFIRMED.** 198 of 261 rows are discharged; **63 are not yet
joined to a ruling.** Detail below. Task 13 stays open on these.

## How a row is discharged

Only a document that rules its file-set **exhaustively** — one that states
"N of N ruled" — discharges a row here. The reason is the standing warning this
manifest was created to enforce: *the slices over-include and do not partition,
so membership is not correspondence.* A document that merely mentions a file does
not rule its rows.

| Document | Claim | Files | Rows here |
|---|---|---|---|
| `2026-08-14-driver-rulings` | 79 of 79 | TotpFactor, OtpFactor, RecoveryCodeFactor | 75 |
| `2026-08-14-exception-rulings` | 46 of 46 | 8 exception classes | 46 |
| `2026-08-14-audience-rulings` | 34 of 34 | ScreenBuilder, IdentifierLinkageViolation | 29 |
| `2026-08-14-integrity-rulings` | 29 of 29 | IntendedDestination, SessionRotationFailed, ChallengeTargetViolation | 29 |
| `2026-08-15-secrets-delivery-rulings` | 12 of 12 | OneTimeSecret, UnconfiguredOtpDelivery | 12 |
| `2026-08-14-provider-rulings` | 56 killed + 6 prose of 62 | VouchServiceProvider | 6 |
| `2026-08-15-matrix-rulings` | matrix row 4, killed on Postgres | EnrollmentGuard | 1 |
| | | **total discharged** | **198** |

Row counts here are lower than each document's claim because rows were killed in
the meantime. A subset of an exhaustively ruled set is still ruled — and no file
gained rows, which is what makes the subset argument sound.

## The 63 rows still needing a join

These sit in files no exhaustive ruling covers. Several are plainly addressed in
`2026-08-15-tail-rulings.md` or `2026-08-15-matrix-rulings.md` per expression,
but those documents make no exhaustive claim, so the correspondence has to be
established row by row rather than asserted.

| File | Rows | Candidate document |
|---|---|---|
| `src/Support/DatabaseTime.php` | 15 | — |
| `src/Http/Middleware/RequireAssurance.php` | 6 | — |
| `src/Vouch.php` | 6 | — |
| `src/Flow/AuthFlow.php` | 5 | — |
| `src/Factors/FactorRegistry.php` | 4 | — |
| `src/Http/AssuranceComparator.php` | 4 | — |
| `src/Models/AuthAttempt.php` | 2 | `2026-08-15-matrix-rulings` |
| `src/Models/AuthCredential.php` | 2 | `2026-08-15-matrix-rulings` |
| `src/Models/AuthConnection.php` | 2 | `2026-08-15-cast-classification` |
| `src/Attempts/DatabaseAttemptStore.php` | 2 | — |
| `src/Console/VouchPruneCommand.php` | 2 | `2026-08-15-tail-rulings` |
| `src/Http/FlowResultSerializer.php` | 2 | `2026-08-15-tail-rulings` |
| `src/Recovery/GraceGuard.php` | 2 | — |
| `src/Factors/FactorResult.php` | 1 | `2026-08-15-tail-rulings` |
| `src/Factors/Drivers/PasswordFactor.php` | 1 | `2026-08-15-tail-rulings` |
| `src/Models/AuthChallenge.php` | 1 | `2026-08-15-matrix-rulings` |
| `src/Models/AuthIdentifier.php` | 1 | `2026-08-15-cast-classification` |
| `src/Models/AuthFederatedIdentity.php` | 1 | `2026-08-15-cast-classification` |
| `src/Models/AuthPolicy.php` | 1 | `2026-08-15-tail-rulings` |
| `src/Http/FlowResultHandler.php` | 1 | `2026-08-15-tail-rulings` |
| `src/Http/AuthController.php` | 1 | `2026-08-15-tail-rulings` |
| `src/Attempts/Mutations/ConsumeChallenge.php` | 1 | `2026-08-15-tail-rulings` |

`DatabaseTime` (15) is the largest single gap and has no candidate document at
all — the same failure mode as `Secrets` and `Notifications`, which were
enumerated in the 2026-08-14 manifest and never ruled because the file-by-file
passes were organised around namespaces that did not include them.

| result | file | line | mutator | id | status | document | basis |
|---|---|---|---|---|---|---|---|
| UNTESTED | src/Attempts/ConflictingMutations.php | 21 | ConcatRemoveLeft | 36abde7c32d49221 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/ConflictingMutations.php | 21 | ConcatRemoveLeft | c34497f6998e54bf | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/ConflictingMutations.php | 21 | ConcatRemoveRight | 89dc80a8d7d42723 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/ConflictingMutations.php | 21 | ConcatRemoveRight | b1e4740ced34d588 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/ConflictingMutations.php | 21 | ConcatSwitchSides | aeb968d362e332c9 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/ConflictingMutations.php | 21 | ConcatSwitchSides | 462475de27a05f16 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/DatabaseAttemptStore.php | 37 | UnwrapArrayValues | 67393e4199909dac | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Attempts/DatabaseAttemptStore.php | 113 | TrueToFalse | 314cd628bbef6df1 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Attempts/MisdirectedMutation.php | 26 | ConcatRemoveLeft | ca89e653f3e58dea | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/MisdirectedMutation.php | 26 | ConcatRemoveLeft | 3372bc225d60a5f3 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/MisdirectedMutation.php | 26 | ConcatRemoveRight | 71b5949f2b8b1ce5 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/MisdirectedMutation.php | 26 | ConcatRemoveRight | 921eee43c7424cdd | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/MisdirectedMutation.php | 26 | ConcatSwitchSides | 8b01aceb557545ea | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/MisdirectedMutation.php | 26 | ConcatSwitchSides | 84cf6249639d4048 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/Mutations/ConsumeChallenge.php | 26 | ConcatSwitchSides | 9866712dc36924f5 | NEEDS JOIN | 2026-08-15-tail-rulings | not exhaustively ruled |
| UNTESTED | src/Attempts/TransitionRefused.php | 25 | ConcatRemoveLeft | 7fa8a31e61d67c59 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/TransitionRefused.php | 25 | ConcatRemoveRight | db3c6704af816935 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/TransitionRefused.php | 25 | ConcatSwitchSides | 8a7d26002751a030 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/TransitionRefused.php | 25 | RemoveMethodCall | c2e993f75ccb8281 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/UnknownMutation.php | 24 | ConcatRemoveLeft | 3cc5835b420bad2f | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/UnknownMutation.php | 24 | ConcatRemoveLeft | b7b2b4985b73c305 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/UnknownMutation.php | 24 | ConcatRemoveRight | 2644d9dfbf572757 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/UnknownMutation.php | 24 | ConcatRemoveRight | ec82ab1c56f81423 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/UnknownMutation.php | 24 | ConcatSwitchSides | e0637cc4c4e5772d | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Attempts/UnknownMutation.php | 24 | ConcatSwitchSides | 8ebdf679df427913 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Console/VouchPruneCommand.php | 41 | DecrementInteger | 916ce1a5cd2fefe4 | NEEDS JOIN | 2026-08-15-tail-rulings | not exhaustively ruled |
| UNTESTED | src/Console/VouchPruneCommand.php | 41 | IncrementInteger | 7245e96a1f5b7ff6 | NEEDS JOIN | 2026-08-15-tail-rulings | not exhaustively ruled |
| UNTESTED | src/Enrollment/EnrollmentGuard.php | 111 | RemoveMethodCall | b771d0690d7ae185 | RULED | 2026-08-15-matrix-rulings | matrix row 4, killed on pgsql |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 25 | DecrementInteger | 292cd184bf37a560 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 25 | IncrementInteger | 65d3477af7df5e68 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 25 | RemoveMethodCall | bf723229c4433210 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 32 | ConcatRemoveLeft | 15f20773d121ae66 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 32 | ConcatRemoveLeft | 3d6be94c0a120cf0 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 32 | ConcatRemoveRight | aef5a8d9faf53cc8 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 32 | ConcatRemoveRight | b9de9bb73a932798 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 32 | ConcatSwitchSides | 8a49b5a2700578c5 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 32 | ConcatSwitchSides | 242ea18cc9074d8e | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 47 | ConcatRemoveLeft | 8c23b95089241a67 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 47 | ConcatRemoveRight | d2183157768a96dc | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Enrollment/EnrollmentRefused.php | 47 | ConcatSwitchSides | db4785940dcb4538 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 64 | ConcatRemoveRight | a586166ec7aa35ee | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 64 | ConcatRemoveRight | f27d4a5134d60ae4 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 64 | ConcatRemoveRight | 137ff9d216cbcc7c | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 64 | ConcatSwitchSides | aa22ea1c9d9b0a8f | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 64 | ConcatSwitchSides | 166a7bea83f97e7f | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 64 | ConcatSwitchSides | fe87b4f4e3544399 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 75 | ConcatRemoveRight | 87f3f3fe316e42fc | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 75 | ConcatRemoveRight | cbca3eed699b0f6c | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 75 | ConcatRemoveRight | 2550a7f5b0df821f | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 75 | ConcatSwitchSides | 5ea2feb7bd52b35b | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 75 | ConcatSwitchSides | d17a08522d39e658 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 75 | ConcatSwitchSides | b8404fbd1f3392c8 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 141 | ConcatRemoveLeft | c1cca452cbdd4d7f | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 141 | ConcatRemoveRight | f3d09fa710e82bbe | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 141 | ConcatSwitchSides | 2e7ca47426cf2603 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 178 | RemoveArrayItem | fbb181a5240dc59e | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 204 | ConcatRemoveLeft | 34bf7ec9b32b1427 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 204 | ConcatRemoveLeft | 60fd12dd70ef3337 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 204 | ConcatRemoveRight | 99d2094898af4fa8 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 204 | ConcatRemoveRight | 2896e004ab17321b | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 204 | ConcatSwitchSides | 8080096e50809869 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 204 | ConcatSwitchSides | 5edfe6edecc86197 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNCOVERED | src/Factors/Drivers/OtpFactor.php | 299 | RemoveEarlyReturn | 0f177138949fd14c | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 381 | ConcatRemoveLeft | b273ea43c63c0f3d | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 381 | ConcatRemoveRight | 1d5f9ae99b4b0c8a | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 381 | ConcatSwitchSides | 2a1d28c1bc225a59 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 391 | InstanceOfToTrue | 5d7ccc8a0c27a163 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/OtpFactor.php | 421 | RemoveStringCast | 9a41b956dfc44c30 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNCOVERED | src/Factors/Drivers/PasswordFactor.php | 133 | RemoveEarlyReturn | 7d7de55a3d58ff0b | NEEDS JOIN | 2026-08-15-tail-rulings | not exhaustively ruled |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 68 | ConcatRemoveRight | 7c746651267a3159 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 68 | ConcatRemoveRight | f09256e980ef6d65 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 68 | ConcatRemoveRight | 4809ca9c8573efa3 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 68 | ConcatSwitchSides | 895a8934653c1c47 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 68 | ConcatSwitchSides | a454ba44ed7c0944 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 68 | ConcatSwitchSides | 4d24842a75a5d958 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatRemoveLeft | bd55c7d82eb25b8a | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatRemoveRight | 9fcf8c2919bbcb1a | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatRemoveRight | 2c41e0e48cf4cf55 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatRemoveRight | 147ac020631b09d5 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatSwitchSides | 1891faf13188f29b | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatSwitchSides | 6e4c331fb00f9404 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatSwitchSides | 8dd6276f865fdca4 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/RecoveryCodeFactor.php | 78 | ConcatSwitchSides | 93dadcd15ac3dfdc | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNCOVERED | src/Factors/Drivers/RecoveryCodeFactor.php | 190 | RemoveEarlyReturn | 13797df0aef85f47 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 63 | ConcatRemoveRight | 016656d9d4b56c25 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 63 | ConcatRemoveRight | 3fd10d48537bb875 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 63 | ConcatRemoveRight | 7bdd9ced1b515510 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 63 | ConcatSwitchSides | 75b88af5f33b7929 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 63 | ConcatSwitchSides | 2cb230be3c50abe7 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 63 | ConcatSwitchSides | 2762b74ecba21f86 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 72 | ConcatRemoveLeft | d74dba56d718ad79 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 72 | ConcatRemoveLeft | 30cb23da82d1355a | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 72 | ConcatRemoveRight | 4397a41cf57c97f5 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 72 | ConcatRemoveRight | 4da1d309cbce6fb7 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 72 | ConcatSwitchSides | f7a2f85ce2b9c816 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 72 | ConcatSwitchSides | 3bd3d7d6302fb67b | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 81 | ConcatRemoveLeft | 7c9e86e98e5a84fd | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 81 | ConcatRemoveLeft | 2acb2724fbe7709d | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 81 | ConcatRemoveRight | bc18eadfafe1aa33 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 81 | ConcatRemoveRight | f3f576c9b258555e | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 81 | ConcatSwitchSides | 79adfd880f221168 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 81 | ConcatSwitchSides | a76458921cc2e2a1 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatRemoveLeft | 503a8cb67369b78a | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatRemoveLeft | a03fba4b89ad34f7 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatRemoveLeft | 0b410f7ff99198cd | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatRemoveRight | 613d6cf338a9fca9 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatRemoveRight | 0340bf2fb9c84f06 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatRemoveRight | fec3bceb991c1509 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatSwitchSides | ca6ef09ce2f8410a | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatSwitchSides | b644e3bfe56cd9a4 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 90 | ConcatSwitchSides | 372f53a7c6ab0a25 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 128 | ConcatRemoveRight | d43c621945d47b04 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 128 | ConcatSwitchSides | a3fbf3b0342d2605 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNCOVERED | src/Factors/Drivers/TotpFactor.php | 192 | RemoveEarlyReturn | b33b87c3674172db | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 280 | PlusToMinus | 825c19b291566c65 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/Drivers/TotpFactor.php | 283 | ContinueToBreak | 72bc7b20776598b8 | RULED | 2026-08-14-driver-rulings | 79 of 79 |
| UNTESTED | src/Factors/FactorRegistry.php | 29 | ConcatRemoveRight | df9acb2e87b685c2 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Factors/FactorRegistry.php | 29 | ConcatRemoveRight | ac11b4c0366d8dd3 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Factors/FactorRegistry.php | 29 | ConcatSwitchSides | 96966b6b4ca66eee | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Factors/FactorRegistry.php | 29 | ConcatSwitchSides | 4c715965861175c0 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Factors/FactorResult.php | 33 | UnwrapArrayValues | 42154a8f487b4873 | NEEDS JOIN | 2026-08-15-tail-rulings | not exhaustively ruled |
| UNTESTED | src/Flow/AuthFlow.php | 101 | RemoveArrayItem | 1d0d951f18ad6bac | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Flow/AuthFlow.php | 236 | RemoveEarlyReturn | 14bd7af547f264a5 | NEEDS JOIN | — | not exhaustively ruled |
| UNCOVERED | src/Flow/AuthFlow.php | 243 | RemoveEarlyReturn | 7c4e64559a2abf6a | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Flow/AuthFlow.php | 329 | RemoveEarlyReturn | 577ee9ed917d58b0 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Flow/AuthFlow.php | 387 | RemoveEarlyReturn | 7b0b64cb43172bbb | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatRemoveRight | cff180f4ea435beb | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatRemoveRight | a01bc7a39a971015 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatRemoveRight | efc9338329236e05 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatRemoveRight | e2d4a6857728d291 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatRemoveRight | 3f18bbcc85abb33a | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatSwitchSides | 243333062c202ef8 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatSwitchSides | 32193b2cdd0f4b35 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatSwitchSides | 3df6ef22682a2915 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatSwitchSides | bb98de7a956f458e | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Flow/ScreenBuilder.php | 80 | ConcatSwitchSides | e651d8597a64d858 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Flow/UnknownFlowResult.php | 23 | ConcatRemoveRight | a9f247272595d581 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Flow/UnknownFlowResult.php | 23 | ConcatSwitchSides | a4f60546e4f0f817 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNCOVERED | src/Http/AssuranceComparator.php | 24 | RemoveArrayItem | 98dc782578dcb775 | NEEDS JOIN | — | not exhaustively ruled |
| UNCOVERED | src/Http/AssuranceComparator.php | 24 | RemoveArrayItem | 9e86faf69f6b7f29 | NEEDS JOIN | — | not exhaustively ruled |
| UNCOVERED | src/Http/AssuranceComparator.php | 24 | RemoveArrayItem | 79f1ecf6f962d77a | NEEDS JOIN | — | not exhaustively ruled |
| UNCOVERED | src/Http/AssuranceComparator.php | 24 | RemoveArrayItem | 5f55f93fd16860d4 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Http/AuthController.php | 43 | TernaryNegated | 0253fa2e4328ff08 | NEEDS JOIN | 2026-08-15-tail-rulings | not exhaustively ruled |
| UNCOVERED | src/Http/FlowResultHandler.php | 40 | TrueToFalse | f05b5809fd295180 | NEEDS JOIN | 2026-08-15-tail-rulings | not exhaustively ruled |
| UNCOVERED | src/Http/FlowResultSerializer.php | 34 | TrueToFalse | 263d34d11d6a1685 | NEEDS JOIN | 2026-08-15-tail-rulings | not exhaustively ruled |
| UNTESTED | src/Http/FlowResultSerializer.php | 70 | UnwrapArrayMap | ac94c754135d6fe0 | NEEDS JOIN | 2026-08-15-tail-rulings | not exhaustively ruled |
| UNTESTED | src/Http/IntendedDestination.php | 76 | BooleanOrToBooleanAnd | 5240669a6894d8ef | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Http/IntendedDestination.php | 76 | StrStartsWithToStrEndsWith | 12ff5467cc00c7b4 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Http/IntendedDestination.php | 77 | RemoveEarlyReturn | 5dafcd2bce6202f8 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Http/IntendedDestination.php | 82 | FalseToTrue | 05ab7e9abb839287 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNCOVERED | src/Http/IntendedDestination.php | 83 | RemoveEarlyReturn | b5703b5474892050 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Http/IntendedDestination.php | 87 | ForeachEmptyIterable | f4d5c20087a9d032 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Http/IntendedDestination.php | 87 | RemoveArrayItem | 895ed1d8a81d6b25 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Http/IntendedDestination.php | 87 | RemoveArrayItem | 99ebca0c4d42f11b | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Http/IntendedDestination.php | 87 | RemoveArrayItem | 3396aa68f34ac230 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Http/IntendedDestination.php | 87 | RemoveArrayItem | 113d048b229bb648 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Http/IntendedDestination.php | 87 | RemoveArrayItem | 3e0ed98e18e36034 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNCOVERED | src/Http/IntendedDestination.php | 89 | RemoveEarlyReturn | ecc9727c2eb89117 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Http/IntendedDestination.php | 95 | BooleanOrToBooleanAnd | dfad39a51184ea74 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNCOVERED | src/Http/IntendedDestination.php | 96 | RemoveEarlyReturn | a328e9134f2d69da | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Http/Middleware/RequireAssurance.php | 51 | ConcatRemoveRight | c78968562c7929e0 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Http/Middleware/RequireAssurance.php | 51 | ConcatRemoveRight | 119fc08faaae9e69 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Http/Middleware/RequireAssurance.php | 51 | ConcatRemoveRight | 7d0cf2a71995c867 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Http/Middleware/RequireAssurance.php | 51 | ConcatSwitchSides | 53b0ea8ef5cc0989 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Http/Middleware/RequireAssurance.php | 51 | ConcatSwitchSides | 62d088bb00f91aa3 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Http/Middleware/RequireAssurance.php | 51 | ConcatSwitchSides | bb1f29f5659446e1 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Models/AuthAttempt.php | 42 | RemoveArrayItem | 76e9c7df97f78ca1 | NEEDS JOIN | 2026-08-15-matrix-rulings | not exhaustively ruled |
| UNTESTED | src/Models/AuthAttempt.php | 65 | DecrementInteger | ce3b9125fc8f18c1 | NEEDS JOIN | 2026-08-15-matrix-rulings | not exhaustively ruled |
| UNTESTED | src/Models/AuthChallenge.php | 39 | RemoveArrayItem | 66f78eb39e411bcd | NEEDS JOIN | 2026-08-15-matrix-rulings | not exhaustively ruled |
| UNCOVERED | src/Models/AuthConnection.php | 34 | RemoveArrayItem | 6119ed96b64ca157 | NEEDS JOIN | 2026-08-15-cast-classification | not exhaustively ruled |
| UNTESTED | src/Models/AuthConnection.php | 59 | DecrementInteger | d6ed9f8b47ad0acd | NEEDS JOIN | 2026-08-15-cast-classification | not exhaustively ruled |
| UNCOVERED | src/Models/AuthCredential.php | 44 | RemoveArrayItem | 4b830fff1cbb9221 | NEEDS JOIN | 2026-08-15-matrix-rulings | not exhaustively ruled |
| UNTESTED | src/Models/AuthCredential.php | 57 | RemoveArrayItem | 91733c3c295cd58c | NEEDS JOIN | 2026-08-15-matrix-rulings | not exhaustively ruled |
| UNTESTED | src/Models/AuthFederatedIdentity.php | 51 | IncrementInteger | 6bd5967292af822a | NEEDS JOIN | 2026-08-15-cast-classification | not exhaustively ruled |
| UNTESTED | src/Models/AuthIdentifier.php | 50 | DecrementInteger | dbaa212386a6d806 | NEEDS JOIN | 2026-08-15-cast-classification | not exhaustively ruled |
| UNTESTED | src/Models/AuthPolicy.php | 45 | DecrementInteger | 1790718caadb3a59 | NEEDS JOIN | 2026-08-15-tail-rulings | not exhaustively ruled |
| UNTESTED | src/Notifications/UnconfiguredOtpDelivery.php | 25 | ConcatRemoveRight | 99de84ef57acce4c | RULED | 2026-08-15-secrets-delivery-rulings | 12 of 12 |
| UNTESTED | src/Notifications/UnconfiguredOtpDelivery.php | 25 | ConcatRemoveRight | a856c15d50459e58 | RULED | 2026-08-15-secrets-delivery-rulings | 12 of 12 |
| UNTESTED | src/Notifications/UnconfiguredOtpDelivery.php | 25 | ConcatRemoveRight | 6ab01e3d670173b7 | RULED | 2026-08-15-secrets-delivery-rulings | 12 of 12 |
| UNTESTED | src/Notifications/UnconfiguredOtpDelivery.php | 25 | ConcatSwitchSides | e0047d7779d8afa2 | RULED | 2026-08-15-secrets-delivery-rulings | 12 of 12 |
| UNTESTED | src/Notifications/UnconfiguredOtpDelivery.php | 25 | ConcatSwitchSides | 534539ab779f7901 | RULED | 2026-08-15-secrets-delivery-rulings | 12 of 12 |
| UNTESTED | src/Notifications/UnconfiguredOtpDelivery.php | 25 | ConcatSwitchSides | d609fd3a94bc5ac8 | RULED | 2026-08-15-secrets-delivery-rulings | 12 of 12 |
| UNTESTED | src/Persistence/ChallengeTargetViolation.php | 21 | ConcatRemoveRight | 433d7c1114fb50e7 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Persistence/ChallengeTargetViolation.php | 21 | ConcatRemoveRight | 7d5e01aa4793d789 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Persistence/ChallengeTargetViolation.php | 21 | ConcatSwitchSides | 5ca775a6b745762a | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Persistence/ChallengeTargetViolation.php | 21 | ConcatSwitchSides | dc21244cae038646 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Persistence/ChallengeTargetViolation.php | 44 | ConcatRemoveRight | 3608d9b285aa439b | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Persistence/ChallengeTargetViolation.php | 44 | ConcatSwitchSides | 371af03870d6250a | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Persistence/ChallengeTargetViolation.php | 47 | RemoveStringCast | 06991a3a633a6884 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 29 | ConcatRemoveRight | d1ade2fbb1793e84 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 29 | ConcatRemoveRight | 5e4463fc3d8d95f5 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 29 | ConcatSwitchSides | c699efe37a3ed883 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 29 | ConcatSwitchSides | 41d754960b368403 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 40 | ConcatRemoveLeft | 91a79912aad87b14 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 40 | ConcatRemoveLeft | 67fc8dc3af2236bd | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 40 | ConcatRemoveRight | b2b692f68f889738 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 40 | ConcatRemoveRight | 0a3921464197b889 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 40 | ConcatSwitchSides | d34cf1f6cf7dad5f | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 40 | ConcatSwitchSides | 5c00e37c4b754904 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatRemoveLeft | cbeead125270e74d | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatRemoveLeft | 3f42da2a4779628d | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatRemoveLeft | cfe2101f1d4424b0 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatRemoveRight | 77c44bc855d9c667 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatRemoveRight | b4dcf2cc1ee8a72b | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatRemoveRight | 7fcc1f79c06c819d | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatSwitchSides | 5bd6d589f667e224 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatSwitchSides | 964ebac2b70cfb9c | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/IdentifierLinkageViolation.php | 50 | ConcatSwitchSides | aa465f4c91d91a32 | RULED | 2026-08-14-audience-rulings | 34 of 34 |
| UNTESTED | src/Persistence/ValueBoundViolation.php | 25 | ConcatRemoveRight | 684c32b46bf4002d | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Persistence/ValueBoundViolation.php | 25 | ConcatSwitchSides | ce7994fbc88de0c1 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Persistence/ValueBoundViolation.php | 37 | ConcatRemoveRight | a24a48ef184a80c2 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Persistence/ValueBoundViolation.php | 37 | ConcatSwitchSides | 681a0a0946c0ed52 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Recovery/GraceGuard.php | 51 | RemoveArrayItem | 536e9917f5e54f39 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Recovery/GraceGuard.php | 52 | RemoveArrayItem | 5510e778d9e30e03 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Secrets/OneTimeSecret.php | 120 | ConcatRemoveLeft | 1ed497e547af8e77 | RULED | 2026-08-15-secrets-delivery-rulings | 12 of 12 |
| UNTESTED | src/Secrets/OneTimeSecret.php | 120 | ConcatRemoveRight | 026cf6eb81bf1bb1 | RULED | 2026-08-15-secrets-delivery-rulings | 12 of 12 |
| UNTESTED | src/Secrets/OneTimeSecret.php | 120 | ConcatSwitchSides | ae220c6000cf23c9 | RULED | 2026-08-15-secrets-delivery-rulings | 12 of 12 |
| UNTESTED | src/Secrets/OneTimeSecret.php | 136 | ConcatRemoveLeft | b1c82f4775ef3de1 | RULED | 2026-08-15-secrets-delivery-rulings | 12 of 12 |
| UNTESTED | src/Secrets/OneTimeSecret.php | 136 | ConcatRemoveRight | af32c0068ee57565 | RULED | 2026-08-15-secrets-delivery-rulings | 12 of 12 |
| UNTESTED | src/Secrets/OneTimeSecret.php | 136 | ConcatSwitchSides | ceb2a09ed82d3b85 | RULED | 2026-08-15-secrets-delivery-rulings | 12 of 12 |
| UNTESTED | src/Secrets/SecretAlreadyRevealed.php | 22 | ConcatRemoveLeft | 5ecf038eb4197d8d | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Secrets/SecretAlreadyRevealed.php | 22 | ConcatRemoveLeft | cd472705a5d4de77 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Secrets/SecretAlreadyRevealed.php | 22 | ConcatRemoveRight | eba74c53baa89613 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Secrets/SecretAlreadyRevealed.php | 22 | ConcatRemoveRight | 7c45f9030acd381d | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Secrets/SecretAlreadyRevealed.php | 22 | ConcatSwitchSides | 4523064c59aa5fa8 | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Secrets/SecretAlreadyRevealed.php | 22 | ConcatSwitchSides | 2777cd01215981bb | RULED | 2026-08-14-exception-rulings | 46 of 46 |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 24 | ConcatRemoveLeft | 1e1909990d210867 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 24 | ConcatRemoveLeft | b5c9658042c66e43 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 24 | ConcatRemoveRight | 2925bbcfcb243ee3 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 24 | ConcatRemoveRight | 663108f87d7850be | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 24 | ConcatSwitchSides | bfe9e31ee08a6c95 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 24 | ConcatSwitchSides | 0542b3c62c814a93 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 27 | DecrementInteger | dd995c1e9fbbec82 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Sessions/SessionRotationFailed.php | 27 | IncrementInteger | caf7632c28b9b279 | RULED | 2026-08-14-integrity-rulings | 29 of 29 |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveLeft | e1f603212532d7fc | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveLeft | 878517133e4bc22e | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveLeft | 1c3ef1b51d011d99 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveLeft | cdcdd50039706af5 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveLeft | d9ba06b40ae28771 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveRight | 81c6ccce0d903556 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveRight | f3f72400856d8a86 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveRight | 61ba222f84be529e | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveRight | f7a7da5a280c3508 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatRemoveRight | a7cf8fb506896371 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatSwitchSides | 5c721da7aa9441d1 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatSwitchSides | 190d2b0a6d9c1658 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatSwitchSides | c4087ff441880b24 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatSwitchSides | 5c2dd311304882a4 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Support/DatabaseTime.php | 60 | ConcatSwitchSides | 2711db478949107e | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Vouch.php | 42 | ConcatRemoveRight | 70158b81a740db68 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Vouch.php | 42 | ConcatRemoveRight | 29e08b8edee83c54 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Vouch.php | 42 | ConcatRemoveRight | e46ec93dd17342bd | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Vouch.php | 42 | ConcatSwitchSides | 0d74f9f9b8392b8c | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Vouch.php | 42 | ConcatSwitchSides | 92603e91ccaa3a97 | NEEDS JOIN | — | not exhaustively ruled |
| UNTESTED | src/Vouch.php | 42 | ConcatSwitchSides | bed924ecd1f40a82 | NEEDS JOIN | — | not exhaustively ruled |
| UNCOVERED | src/VouchServiceProvider.php | 246 | ConcatRemoveLeft | 9411bf339acdc9a5 | RULED | 2026-08-14-provider-rulings | 62 of 62 |
| UNCOVERED | src/VouchServiceProvider.php | 246 | ConcatRemoveLeft | ac7b717c78e615aa | RULED | 2026-08-14-provider-rulings | 62 of 62 |
| UNCOVERED | src/VouchServiceProvider.php | 246 | ConcatRemoveRight | 414cbf21a1c8b8fc | RULED | 2026-08-14-provider-rulings | 62 of 62 |
| UNCOVERED | src/VouchServiceProvider.php | 246 | ConcatRemoveRight | 27fcaeaa1544a931 | RULED | 2026-08-14-provider-rulings | 62 of 62 |
| UNCOVERED | src/VouchServiceProvider.php | 246 | ConcatSwitchSides | ca8cd6e1f3538158 | RULED | 2026-08-14-provider-rulings | 62 of 62 |
| UNCOVERED | src/VouchServiceProvider.php | 246 | ConcatSwitchSides | f0d91d34137b668a | RULED | 2026-08-14-provider-rulings | 62 of 62 |
