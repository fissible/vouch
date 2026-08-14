<?php

declare(strict_types=1);

use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Enrollment\EnrollmentRefusalReason;
use Fissible\Vouch\Enrollment\EnrollmentRefused;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;
use Illuminate\Database\QueryException;

/*
 * isLockContention() decides whether a database error means "somebody else is
 * enrolling, retry" or "your schema is broken, do not retry". Getting it wrong
 * in either direction is a real defect: too narrow and ordinary contention
 * surfaces as SQLSTATE noise; too wide and a dropped table is reported as
 * transient, so the caller retries forever against a fault that will never clear.
 *
 * Real contention on MySQL and Postgres needs those engines, which is the
 * cross-engine matrix's job. What this file pins is the MAPPING — that each
 * engine's documented contention code, and only it, reaches the refusal — and
 * that mapping is a pure function of the driver name and the error codes. So the
 * engine is the one thing worth substituting here.
 *
 * The substitution is deliberately shallow: one seam, affectingStatement(), the
 * exact call insertOrIgnore() makes. The real Builder compiles the real SQL and
 * the real guard runs its real catch block. tests/Database/EnrollmentGuardErrorsTest.php
 * anchors this against a genuine SQLite error from a genuinely missing table, so
 * a double that lied about the shape of a QueryException would be caught there.
 */

/** A PDOException carrying the SQLSTATE and driver code a real engine would report. */
final class ProbeDriverException extends PDOException
{
    public function __construct(string $sqlstate, ?int $driverCode)
    {
        parent::__construct('probe failure');

        // Laravel's QueryException copies both of these off the previous
        // exception, which is where the guard reads them from.
        $this->code = $sqlstate;
        $this->errorInfo = [$sqlstate, $driverCode, 'probe failure'];
    }
}

/** A connection that names any driver and fails the lock claim with a chosen error. */
final class ClassifierProbeConnection extends Connection
{
    public function __construct(private readonly string $driver, private readonly QueryException $failure)
    {
        // The probe must never open a connection: every query it could run
        // is intercepted below, so reaching for a PDO is itself the bug.
        parent::__construct(
            static fn (): PDO => throw new RuntimeException('The classifier probe must not open a PDO.'),
            'probe',
            '',
            ['driver' => $driver],
        );
    }

    public function getDriverName(): string
    {
        return $this->driver;
    }

    /**
     * The base grammar refuses to compile insert-or-ignore at all, so a real one
     * is needed to reach the seam. Which one is immaterial: the SQL it produces
     * is never executed — affectingStatement() throws on receipt.
     */
    protected function getDefaultQueryGrammar(): SQLiteGrammar
    {
        return new SQLiteGrammar($this);
    }

    /** @param  Closure(static): mixed  $callback */
    public function transaction(Closure $callback, $attempts = 1): mixed
    {
        return $callback($this);
    }

    /**
     * boundTheWait()'s engine setting — irrelevant to classification, so a no-op.
     *
     * @param  array<int|string, mixed>  $bindings
     */
    public function statement($query, $bindings = []): bool
    {
        return true;
    }

    /**
     * The call insertOrIgnore() makes.
     *
     * @param  array<int|string, mixed>  $bindings
     */
    public function affectingStatement($query, $bindings = []): int
    {
        throw $this->failure;
    }
}

function classifierGuard(string $driver, string $sqlstate, ?int $driverCode): EnrollmentGuard
{
    $failure = new QueryException(
        'probe',
        'insert or ignore into "auth_enrollment_locks" ("type", "user_id") values (?, ?)',
        ['password', 7],
        new ProbeDriverException($sqlstate, $driverCode),
    );

    return new EnrollmentGuard(new ClassifierProbeConnection($driver, $failure), lockWaitSeconds: 5);
}

it('classifies each engine documented contention code as contention', function (string $driver, string $sqlstate, ?int $code): void {
    /*
     * MySQL 1205 and SQLite 5 both arrive under SQLSTATE HY000, the general-error
     * catch-all, so the driver code is the only discriminator. Postgres is the
     * one engine that gives contention its own SQLSTATE.
     */
    try {
        classifierGuard($driver, $sqlstate, $code)->serialize(7, 'password', 1, fn (): bool => true);
        $this->fail('Expected EnrollmentRefused for ' . $driver . ' ' . $sqlstate . '/' . var_export($code, true));
    } catch (EnrollmentRefused $refused) {
        expect($refused->reason)->toBe(EnrollmentRefusalReason::Contended);
    }
})->with([
    'mysql lock wait timeout' => ['mysql', 'HY000', 1205],
    'pgsql lock not available' => ['pgsql', '55P03', 7],
    'sqlite busy' => ['sqlite', 'HY000', 5],
]);

it('rethrows anything it has not verified as contention', function (string $driver, string $sqlstate, ?int $code): void {
    /*
     * EnrollmentRefused::contended() tells the caller the operation is safe to
     * retry. For a missing table that advice is wrong and unbounded — the retry
     * can never succeed. The missing-table codes below are the measured ones;
     * the last case is an engine nobody has probed.
     */
    classifierGuard($driver, $sqlstate, $code)->serialize(7, 'password', 1, fn (): bool => true);
})->with([
    'mysql missing table' => ['mysql', '42S02', 1146],
    'pgsql missing table' => ['pgsql', '42P01', 7],
    'sqlite missing table' => ['sqlite', 'HY000', 1],
    // MySQL's own contention code on an engine whose behaviour was never
    // measured: the default arm must still refuse to guess.
    'unknown engine' => ['oracle', 'HY000', 1205],
    'absent error info' => ['sqlite', 'HY000', null],
])->throws(QueryException::class);

it('does not treat one engine contention code as another engine', function (): void {
    /*
     * The codes are not interchangeable: SQLite 5 is SQLITE_BUSY, MySQL 5 is
     * nothing in particular. Without this, the match arms could collapse into a
     * single "is the code 1205 or 5" test and both contention cases above would
     * still pass.
     */
    classifierGuard('mysql', 'HY000', 5)->serialize(7, 'password', 1, fn (): bool => true);
})->throws(QueryException::class);
