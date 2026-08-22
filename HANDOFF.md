# Vouch reboot handoff — mutation reconciliation

## Checkpoint

- Repository: `/Users/allenmccabe/lib/fissible/vouch`
- Branch: `main`
- Tree: clean
- Documentation checkpoint: `6f24b58` (`docs: add mutation reconciliation ledger`)
- Mutation baseline SHA: `66ac67d`
- Do not measure against a different SHA. Before every run:

```sh
test "$(git rev-parse HEAD)" = 66ac67d && echo PIN_OK
```

The committed ledger is
`docs/superpowers/mutation/2026-08-22-reconciliation-ledger.md`.

## Completed measurements at `66ac67d`

All measurements used the patched Pest mutation plugin and file-backed,
`TEST_TOKEN`-scoped SQLite.

| scope | result | artifact |
|---|---|---|
| Delivery | 229 mutations; 164 tested, 64 untested, 1 uncovered, 0 timeouts; 137.63s; threshold 37.69s | `/tmp/vouch-delivery-66ac67d.log` |
| Flow/AuthFlow only | 285 mutations; 272 tested, 12 untested, 1 uncovered, 0 timeouts; 239.82s; threshold 36.82s | `/tmp/vouch-authflow-66ac67d.log` |
| Throttle | 865 mutations; 736 tested, 89 untested, 40 uncovered, 0 timeouts; 3,165.85s; threshold 37.28s | `/tmp/vouch-throttle-66ac67d.log` |

Flow is **not complete**: nine Flow files remain, especially
`VerificationEqualizer` and `ScreenBuilder`.

The 91-file / 3,155-mutation count came from a parallel smoke run and remains
provisional. It must be replaced by the sum of authoritative non-compact
`RUN` lists from all seven ledger chunks. The parallel result credited 53
timeouts and is not a ruling artifact; verified kills were 2,545 / 3,155
(80.66%), not the displayed 82.35%.

## Next action: Kernel

Run Kernel before the smaller Console and Notifications chunks. Kernel is
disclosure-sensitive and broadly routed, so its survivors may require design
decisions rather than only test additions.

Use the exact baseline guard and a non-compact, sequential, file-backed run;
record the initial suite duration and Pest’s timeout threshold in the ledger.
The scope is `src/Kernel/` (26 source files), including:

- `Kernel/Enumeration/ErrorShaper.php` — sole disclosure authority.
- `Kernel/Screen/ScreenSpec.php` — CAPTCHA surface amendment.
- `Kernel/Screen/RetryPolicy.php` — 2.3b retry disclosure amendment.

Do not land tests or source changes discovered while ruling. Queue them until
all chunks are measured, then apply the queued set and run one confirming full
mutation pass at the new SHA.

## Remaining ledger order

1. Kernel (next; 26 files).
2. Console (8 files).
3. Notifications (8 files).
4. Remaining Flow files (9 files, separate from the already measured AuthFlow).
5. Core sub-runs: Attempts, Contracts, Enrollment, Factors, Http, Jobs,
   Models, Persistence, Recovery, Secrets, Sessions, Support, Tenancy, and
   the two root files. Models and broad Core paths are expected to be slow.

The ledger already itemizes all 162 source files across these assignments.
The 91 mutant-bearing-file total is provisional until the authoritative RUN
lists are available.

## Interpretation rules

- Keep tested kills, untested rows, uncovered rows, and timeouts separate.
- A timeout is unresolved, not automatically killed.
- A newly added/routed test may move a row from uncovered to untested. That is
  instrument clarification, not a regression; Delivery demonstrated this.
- The Throttle hypothesis that observe-mode defaults caused its 40 uncovered
  rows was checked and rejected; 17 test files exercise enforce mode.
- Membership is the stable `(file, mutator, expression)` tuple, never a
  filename-only or mutator-family ruling.
- Check `tests/Mutation/FilterChunkingTest.php` first if a large UNTESTED batch
  appears; that indicates harness routing failure rather than code evidence.

## Ordinary validation

At the checkpoint before mutation work, the ordinary suite was green with
file-backed SQLite (1,161 passed, 0 skipped, 4,092 assertions) and PHPStan
level 9 was clean. Preserve the clean tree while measuring.
