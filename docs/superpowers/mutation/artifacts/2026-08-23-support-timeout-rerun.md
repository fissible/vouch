# Support timeout rerun

- Source state: `bb549ed`; guarded paths unchanged from `66ac67d`.
- Mutation: `src/Support/BoundedLockWait.php:65`, `RemoveMethodCall` on
  `writeSeconds()` (temporary mutated source restored after the run).
- Test: `tests/Concurrency/BoundedLockWaitContentionTest.php` on file-backed
  SQLite, with the ambient 47-second setting used by the contention fixture.
- Result: one test failed after 49.15s because the measured contention elapsed
  time was 48.83s, violating the explicit `<10.0s` bound assertion.
- Disposition: `killed-by-bounded-slow`. The mutation is not an infinite loop;
  it removes the intended one-second narrowing and leaves the host setting in
  place, making the bounded path observably too slow.
