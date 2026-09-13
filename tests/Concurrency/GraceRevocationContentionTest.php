<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Recovery\GraceGuard;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;

/*
 * Issue #36 -- a revocation arriving while grace is opening must win.
 *
 * The guard against reviving a revoked row is a read followed by a write, and
 * between those two a password change on another device can land. Checked in
 * PHP against a row read earlier, the write then clears a revocation it never
 * saw -- which is the same defect reached by timing instead of by state, and
 * precisely the window a locking re-read inside the transaction closes.
 *
 * DatabaseMigrations rather than RefreshDatabase: the racing process cannot see
 * an uncommitted transaction, so the revocation would be invisible and the test
 * would pass having raced nothing.
 */
uses(DatabaseMigrations::class);

beforeEach(function (): void {
    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped('Contention tests need a shared database.');
    }

    if (! function_exists('pcntl_fork')) {
        $this->markTestSkipped('A genuine interleave needs pcntl_fork.');
    }
});

function contendedGraceBinding(): string
{
    return SessionBinding::for('host-session-race', BindingDomain::Session);
}

it('keeps a revocation that lands while grace is opening', function (): void {
    /*
     * The revoking writer is released from inside grace's own first statement,
     * so it acts while start() is mid-flight rather than merely at the same
     * moment. Whichever commits first, the row must not end up live: a
     * revocation is not something a concurrent grace may undo.
     */
    AuthSession::create([
        'session_binding' => contendedGraceBinding(),
        'user_id' => 7,
        'amr' => ['password'],
    ]);

    $directory = sys_get_temp_dir() . '/vouch-grace-race-' . bin2hex(random_bytes(8));

    if (! mkdir($directory, 0700) && ! is_dir($directory)) {
        throw new RuntimeException('Could not create the grace barrier directory.');
    }

    $release = $directory . '/release';
    $report = $directory . '/report';

    DB::disconnect();

    $pid = pcntl_fork();

    if ($pid === -1) {
        throw new RuntimeException('Could not fork the revoking writer.');
    }

    if ($pid === 0) {
        $connection = DB::connection();

        try {
            $connection->getPdo();

            if ($connection->getDriverName() === 'sqlite') {
                $connection->statement('PRAGMA busy_timeout = 5000');
            }

            $deadline = microtime(true) + 10.0;

            while (! is_file($release)) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('The revoking writer was never released.');
                }

                usleep(500);
            }

            $affected = $connection->table('auth_sessions')
                ->where('session_binding', contendedGraceBinding())
                ->whereNull('revoked_at')
                ->update([
                    'revoked_at' => now(),
                    'revoked_reason' => RevokedReason::PasswordChanged->value,
                ]);

            // Report what it actually did. An update matching no rows is not a
            // revocation, and counting it as one would let this test conclude
            // that grace preserved something nobody wrote.
            file_put_contents($report, $affected === 1 ? 'revoked' : 'matched-nothing');
            exit(0);
        } catch (Throwable $exception) {
            file_put_contents(
                $report,
                (isContentionFailure($connection, $exception) ? 'contention:' : 'error:') . $exception::class,
            );
            exit(1);
        }
    }

    $parent = DB::connection();

    if ($parent->getDriverName() === 'sqlite') {
        $parent->statement('PRAGMA busy_timeout = 5000');
    }

    /*
     * Released AFTER grace's first statement against auth_sessions completes,
     * through the query log rather than beforeExecuting -- and both halves of
     * that matter.
     *
     * beforeExecuting fires BEFORE the statement runs, so the revoker committed
     * during the pause and grace's read then saw it. The stale read never
     * happened and a non-locking implementation passed.
     *
     * And releasing on a SELECT specifically required the implementation to
     * issue one. A conditional upsert whose ON CONFLICT clause refuses revoked
     * or foreign-subject rows is correct and reads nothing, so it never
     * released the writer at all and failed a race it had already won. Keying
     * on the first auth_sessions statement of any shape covers both.
     *
     * What each shape then does:
     *   - unlocked read, PHP check, write -> the revocation commits in the gap
     *     and the write clears it. The row ends live, which fails below.
     *   - locking read inside a transaction -> the revoker BLOCKS here instead
     *     and lands after grace commits. The row ends revoked.
     *   - conditional upsert -> grace has already written; the revoker then
     *     revokes the row it finds. The row ends revoked.
     */
    $released = false;

    DB::listen(function ($query) use ($release, $report, &$released): void {
        if ($released || ! str_contains($query->sql, 'auth_sessions')) {
            return;
        }

        $released = true;
        touch($release);

        /*
         * Wait for the writer, but only briefly. A locking implementation
         * blocks it until grace commits, so insisting on its report would
         * deadlock the very implementation this test is meant to accept.
         */
        $deadline = microtime(true) + 0.3;

        while (! is_file($report) && microtime(true) < $deadline) {
            usleep(1_000);
        }
    });

    app(GraceGuard::class)->start('host-session-race', 7);

    pcntl_waitpid($pid, $status);

    $outcome = is_file($report) ? (string) file_get_contents($report) : 'missing';

    // The interleave happened, and the other writer lost cleanly if it lost.
    expect($released)->toBeTrue()
        ->and($outcome === 'revoked' || str_starts_with($outcome, 'contention:'))->toBeTrue(
            "the revoking writer did not finish cleanly: {$outcome}",
        );

    if ($outcome !== 'revoked') {
        /*
         * Skipped rather than passed, and the distinction matters: a run where
         * the revocation never landed has not tested anything, and letting it
         * report green would hide exactly the schedule this test exists for.
         */
        $this->markTestSkipped("No revocation raced this grace ({$outcome}), so nothing was exercised.");
    }

    $row = requiredRow(DB::table('auth_sessions')->where('session_binding', contendedGraceBinding())->first());

    expect($row->revoked_at)->not->toBeNull('A concurrent grace undid the revocation.')
        ->and(stringValue($row->revoked_reason))->toBe(RevokedReason::PasswordChanged->value)
        ->and(app(GraceGuard::class)->activeFor('host-session-race'))->toBeNull();
});
