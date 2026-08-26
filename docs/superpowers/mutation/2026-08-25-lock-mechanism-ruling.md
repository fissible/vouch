# Pessimistic-lock mechanism ruling

Closes the lock-mechanism ruling opened during the 2.3b/2.3c mutation
reconciliation, covering surviving mutants in `DatabaseAuthThrottleStore`,
`DatabaseDeliveryEconomics`, `DatabaseRowLock` and `EnrollmentGuard`.

## Why the mutants survive

`Illuminate\Database\Query\Grammars\SQLiteGrammar::compileLock()` returns `''`.
On SQLite, `lockForUpdate()` emits no SQL at all, so every mutant that removes,
negates or bypasses it produces byte-identical statements. All mutation
measurement in this reconciliation ran on SQLite. The rows are therefore
**engine-equivalent**: unkillable under the measuring engine by construction,
not undertested.

That is a limit on the instrument, not a finding about the code. The source
already documented it, in `ensureCounter()`:

> SQLite's FOR UPDATE is a bare SELECT. Make the unique insert the first
> statement so the transaction claims the global writer lock before any
> state-bearing read.

No test can move these rows while measurement runs on SQLite. They are closed
by this ruling rather than by a kill, and any future confirmation run should
expect them to persist.

## Where the locks are load-bearing

Read from the call sites rather than measured, and mixed by path:

| path | verdict |
|---|---|
| `DatabaseAuthThrottleStore` read/decide/write | **load-bearing** — `counter(lock: true)` → `identifierState()` → increment. Without the lock two requests both read count = 4, both permit, both increment; one attempt passes the threshold. |
| `DatabaseDeliveryEconomics` ceiling enforcement | **redundant** — `UPDATE ... WHERE spent_minor <= ceiling - cost` is one statement. The predicate and increment are atomic and `$updated !== 1` detects breach. The earlier locked read contributes nothing. |
| `DatabaseDeliveryEconomics` daily rollover | **load-bearing** — the reset is unconditional and follows a read. Two workers seeing a stale window both zero `spent_minor`, discarding a concurrent increment. |

Keeping the locks everywhere is the correct disposition. Removing them is off
the table because two of the three paths need them, and the third's redundancy
is not worth the divergence.

## What the probes establish

`tests/Concurrency/DeliveryEconomicsContentionTest.php` — "preserves a
concurrent spend while a stale window rolls over" — forks a child, holds the
seeded global spend row from the parent, rolls the window to today with
`spent_minor = 20`, then releases the child's `reserve()`.

Three assertions carry the evidence:

1. After the barrier releases, the child has produced no output — it blocked
   rather than proceeding on a stale read.
2. The child exits 0 with `Permitted`.
3. Final `spent_minor` is **30**, the parent's 20 plus the child's 10.

Assertion 3 is the discriminating one. Had the child proceeded on its stale
read, it would have reset the window to today with `spent_minor = 0` and
incremented to 10, destroying the parent's concurrent spend.

**On PostgreSQL and MySQL this is mechanism evidence.** Remove the child's
`lockForUpdate()` and its plain `SELECT` returns immediately under READ
COMMITTED with the stale row; the subsequent unconditional reset then
overwrites the parent's 20 and the final value is 10, not 30. The probe would
fail. The lock is doing the work the code claims it does.

## What the probes do not establish

**Nothing about SQLite's mechanism.** The parent must issue `BEGIN IMMEDIATE`
explicitly, because `lockForUpdate()` emits nothing there. The child then
blocks on SQLite's global writer lock, which it would do with or without the
production lock call. On SQLite the probe demonstrates that the invariant holds
under forced serialization — evidence about the harness, not about
`lockForUpdate()`. Production's SQLite safety rests on the insert-first
ordering in `ensureCounter()`, which this probe does not exercise.

**Nothing about the throttle store's read/decide/write path.** The probe covers
delivery rollover only. `DatabaseAuthThrottleStore`'s lost-update hazard is
argued from isolation semantics and remains unmeasured. The scalar contention
harness proves the counter invariant holds; it does not force the schedule that
would fail without the lock, which is the distinction recorded in `24e41ec`.

**Nothing about `EnrollmentGuard` or `DatabaseRowLock` predicates.** Their
surviving rows are engine-equivalent for the same `compileLock()` reason and
carry no probe of their own.

## Residual

- A PostgreSQL read/decide/write interleaving probe for the throttle store
  would convert its load-bearing claim from reasoning to measurement. It is the
  one outstanding piece of this ruling.
- `BoundedLockWait:112` (`$seconds . 's'`) is separately covered: PostgreSQL
  reads a unitless `lock_timeout` as milliseconds, so dropping the suffix is a
  thousandfold change, invisible on SQLite. Asserted in
  `tests/Database/BoundedLockWaitTest.php`.
