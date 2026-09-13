<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Recovery\CredentialRecovery;
use Fissible\Vouch\Recovery\CredentialRecoveryRequest;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Schema;

/*
 * DatabaseMigrations, NOT RefreshDatabase -- the same reason as the other
 * contention suites. RefreshDatabase wraps each test in a transaction on the
 * default connection, so forked children could not see the seeded account and
 * every "racing" writer would operate on an empty table.
 */
uses(DatabaseMigrations::class);

beforeEach(function (): void {
    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'Contention tests need a shared database. In-memory SQLite gives each connection '
            . 'its own, so these would pass without racing. Set VOUCH_SQLITE_PATH to a file, '
            . 'as the CI matrix and the suite bootstrap both do.',
        );
    }

    if (! function_exists('pcntl_fork')) {
        $this->markTestSkipped('A genuine interleave needs pcntl_fork.');
    }
});

function contendedRecoveryRequest(): CredentialRecoveryRequest
{
    return new CredentialRecoveryRequest(
        type: 'email',
        submittedIdentifier: 'ada@acme.example',
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

function contendedAccount(): void
{
    AuthIdentifier::create([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => now(),
    ]);

    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(1, ['password' => 'old-password']);
}

/**
 * Rows that could still be redeemed: unconsumed, unsuperseded, unexpired.
 *
 * The column check is not defensive noise. SQLite resolves a double-quoted
 * identifier it does not recognise as a STRING LITERAL, so `whereNull` on a
 * missing column matches nothing and returns 0 -- a count that reads like "no
 * live proofs" and would let this fixture pass against an implementation that
 * never built the column. MySQL and PostgreSQL error on the same query, so the
 * vacancy is engine-specific too.
 */
function stillRedeemableCount(): int
{
    foreach (['consumed_at', 'superseded_at'] as $column) {
        if (! Schema::hasColumn('auth_recovery_proofs', $column)) {
            throw new RuntimeException(
                "auth_recovery_proofs has no {$column} column, so this count cannot mean what it says.",
            );
        }
    }

    return DB::table('auth_recovery_proofs')
        ->whereNull('consumed_at')
        ->whereNull('superseded_at')
        ->whereRaw('expires_at > CURRENT_TIMESTAMP')
        ->count();
}

/**
 * Issue the same recovery code from separate PROCESSES, released together.
 *
 * Forked children rather than two calls on one stack. `request()` resolves its
 * outbox from the container, which is bound to the default connection, so
 * naming a second connection in the same process changes nothing: both calls
 * still run sequentially on one handle and the "race" is two ordinary
 * requests. Only independent processes contend for real.
 *
 * @return list<string> what each child reported: 'issued', or an exception class
 */
function raceRecoveryIssuance(int $count): array
{
    $directory = sys_get_temp_dir() . '/vouch-issue-race-' . bin2hex(random_bytes(8));

    if (! mkdir($directory, 0700) && ! is_dir($directory)) {
        throw new RuntimeException('Could not create the issuance barrier directory.');
    }

    $release = $directory . '/release';
    $children = [];

    // SQLite connections are not fork-safe even if the child purges its
    // inherited PDO. Close the seed connection before forking; every process
    // opens its own handle afterwards.
    DB::purge();

    foreach (range(0, $count - 1) as $index) {
        $pid = pcntl_fork();

        if ($pid === -1) {
            throw new RuntimeException('Could not fork an issuance child.');
        }

        if ($pid === 0) {
            $output = $directory . "/output-{$index}";

            try {
                $connection = DB::connection();
                $connection->getPdo();

                if ($connection->getDriverName() === 'sqlite') {
                    // Without this, SQLITE_BUSY fails instantly rather than
                    // waiting its turn, and the race resolves as an error
                    // rather than as contention.
                    $connection->statement('PRAGMA busy_timeout = 5000');
                }

                file_put_contents($directory . "/database-{$index}", $connection->getDatabaseName());
                touch($directory . "/ready-{$index}");

                $deadline = microtime(true) + 10.0;

                while (! is_file($release)) {
                    if (microtime(true) >= $deadline) {
                        throw new RuntimeException('Timed out waiting for the issuance release.');
                    }

                    usleep(1_000);
                }

                app(CredentialRecovery::class)->request(contendedRecoveryRequest());

                // "returned", not "issued": a loser is allowed to refuse by
                // returning normally after rolling back, so a normal return
                // does NOT mean a proof was written. The parent counts rows.
                file_put_contents($output, 'returned');
                exit(0);
            } catch (Throwable $exception) {
                /*
                 * Class AND driver state. "Contains Exception" accepts a
                 * TypeError-adjacent RuntimeException from a broken
                 * implementation, which would read as acceptable contention;
                 * a database contention failure carries a SQLSTATE.
                 */
                $state = $exception instanceof \PDOException ? (string) $exception->getCode() : '';

                if ($exception instanceof QueryException) {
                    $state = (string) ($exception->errorInfo[0] ?? $exception->getCode());
                }

                file_put_contents($output, 'threw|' . $exception::class . '|' . $state);
                exit(1);
            }
        }

        $children[$index] = $pid;
    }

    $barrierDeadline = microtime(true) + 10.0;

    foreach (array_keys($children) as $index) {
        while (! is_file($directory . "/ready-{$index}")) {
            if (microtime(true) >= $barrierDeadline) {
                throw new RuntimeException('An issuance child never reached the barrier.');
            }

            usleep(1_000);
        }
    }

    $parentDatabase = DB::connection()->getDatabaseName();

    foreach (array_keys($children) as $index) {
        $childDatabase = (string) file_get_contents($directory . "/database-{$index}");

        // Children racing on separate databases would contend for nothing, and
        // every assertion below would hold vacuously.
        if ($childDatabase !== $parentDatabase) {
            throw new RuntimeException("Issuance child {$index} used a different database.");
        }
    }

    touch($release);

    $reports = [];

    foreach ($children as $index => $pid) {
        pcntl_waitpid($pid, $status);
        $reports[] = (string) file_get_contents($directory . "/output-{$index}");
    }

    return $reports;
}

it('leaves exactly one live proof when issuances genuinely race', function (): void {
    /*
     * The resend-button double-click, as a real race.
     *
     * If every process reads "no prior live proof" before any of them writes,
     * each creates a proof and supersedes nothing, and the user holds several
     * usable password-reset capabilities -- the defect, reached without anyone
     * doing anything unusual.
     *
     * The invariant names no mechanism. Whether a loser blocks and then
     * supersedes, throws a contention error, or rolls back and returns
     * normally, ONE live proof is the only acceptable end state.
     *
     * WHAT THIS IS AND IS NOT. A release barrier makes the processes compete;
     * it cannot force them to overlap at the one operation that matters, so
     * this DETECTS a non-serializing implementation rather than proving
     * serialization. A measured counterexample -- supersede in autocommit, then
     * insert transactionally -- survived a single race about three times in
     * four, so the race is repeated: eight rounds put detection near nine in
     * ten, and repetition costs a correct implementation nothing, because it
     * wins every round. Deterministic proof would need a hook inside issuance,
     * and that is recorded as a gap rather than faked here.
     */
    contendedAccount();
    app()->instance(OtpDelivery::class, new ArrayOtpDelivery());
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    foreach (range(1, 8) as $round) {
        DB::table('auth_recovery_proof_outbox')->delete();
        DB::table('auth_recovery_proofs')->delete();

        $reports = raceRecoveryIssuance(3);

        foreach ($reports as $report) {
            /*
             * A loser may refuse, and it may refuse EITHER WAY: by throwing a
             * database contention error, or by returning normally after
             * rolling back. What it may not do is fail through a programming
             * error -- so a throw has to carry a driver SQLSTATE rather than
             * merely being some exception class with "Exception" in the name.
             */
            if (str_starts_with($report, 'threw|')) {
                [, $class, $state] = explode('|', $report, 3);

                expect($state)->not->toBe('', "a racing child failed without a driver state: {$class}");

                continue;
            }

            expect($report)->toBe('returned', "a racing child reported something unrecognised: {$report}");
        }

        // Someone won, or "one live proof" would be satisfied by a race in
        // which nothing happened at all. Counted from ROWS rather than from
        // normal returns, because a refusing loser also returns normally.
        expect(DB::table('auth_recovery_proofs')->count())->toBeGreaterThan(0);

        /*
         * The invariant, stated twice over: one proof that could still be
         * redeemed, and exactly one row not marked superseded. The second
         * catches a row left live-but-unsuperseded that the first would miss
         * if it happened to be expired.
         */
        expect(stillRedeemableCount())->toBe(1)
            ->and(DB::table('auth_recovery_proofs')->whereNull('superseded_at')->count())->toBe(1);
    }
});

it('leaves exactly one live proof across repeated rapid issuance', function (): void {
    /*
     * The sequential companion. It cannot show serialization -- each request
     * reads the previous one's committed row -- but it does show supersession
     * accumulating rather than retiring only the proof immediately before it.
     */
    contendedAccount();
    app()->instance(OtpDelivery::class, new ArrayOtpDelivery());
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    foreach (range(1, 5) as $ignored) {
        app(CredentialRecovery::class)->request(contendedRecoveryRequest());
    }

    expect(DB::table('auth_recovery_proofs')->count())->toBe(5)
        ->and(stillRedeemableCount())->toBe(1);
});
