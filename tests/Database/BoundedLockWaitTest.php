<?php

declare(strict_types=1);

use Fissible\Vouch\Support\BoundedLockWait;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

function boundedWaitSettingText(string $query): string
{
    $value = DB::connection()->scalar($query);

    return match (true) {
        is_int($value) => (string) $value,
        is_string($value) => $value,
        default => throw new RuntimeException('Non-scalar readback from: ' . $query),
    };
}

function boundedWaitPostgresMs(string $shown): int
{
    return match (true) {
        str_ends_with($shown, 'ms') => (int) $shown,
        str_ends_with($shown, 's') => (int) $shown * 1000,
        default => (int) $shown,
    };
}

function boundedWaitCurrentMs(): int
{
    return match (DB::connection()->getDriverName()) {
        'sqlite' => (int) boundedWaitSettingText('PRAGMA busy_timeout'),
        'mysql' => (int) boundedWaitSettingText('SELECT @@SESSION.innodb_lock_wait_timeout') * 1000,
        'pgsql' => boundedWaitPostgresMs(boundedWaitSettingText('SHOW lock_timeout')),
        default => throw new RuntimeException('No lock-wait readback for this driver.'),
    };
}

function boundedWaitSetMs(int $milliseconds): void
{
    $connection = DB::connection();

    match ($connection->getDriverName()) {
        'sqlite' => $connection->statement(sprintf('PRAGMA busy_timeout = %d', $milliseconds)),
        'mysql' => $connection->statement(
            sprintf('SET SESSION innodb_lock_wait_timeout = %d', intdiv($milliseconds, 1000)),
        ),
        'pgsql' => $connection->scalar(
            "SELECT set_config('lock_timeout', ?, false)",
            [$milliseconds . 'ms'],
        ),
        default => throw new RuntimeException('No lock-wait setter for this driver.'),
    };
}

/**
 * @template TResult
 *
 * @param  callable(): TResult  $test
 * @return TResult
 */
function withParkedBoundedWait(callable $test): mixed
{
    $original = boundedWaitCurrentMs();
    boundedWaitSetMs(47_000);

    expect(boundedWaitCurrentMs())->toBe(47_000);

    try {
        return $test();
    } finally {
        boundedWaitSetMs($original);
    }
}

it('applies the bound inside the critical section and restores the exact prior value', function (): void {
    withParkedBoundedWait(function (): void {
        $result = (new BoundedLockWait(DB::connection()))->enrollment(3, function (): string {
            expect(boundedWaitCurrentMs())->toBe(3_000);

            return 'completed';
        });

        expect($result)->toBe('completed')
            ->and(boundedWaitCurrentMs())->toBe(47_000);
    });
});

it('preserves seconds as the PostgreSQL lock-timeout unit', function (): void {
    if (DB::connection()->getDriverName() !== 'pgsql') {
        $this->markTestSkipped('PostgreSQL lock_timeout units are only available on PostgreSQL.');
    }

    withParkedBoundedWait(function (): void {
        (new BoundedLockWait(DB::connection()))->enrollment(3, function (): void {
            expect(boundedWaitSettingText('SHOW lock_timeout'))->toBe('3s');
        });
    });
});

it('restores the prior value when the caller throws', function (): void {
    withParkedBoundedWait(function (): void {
        $failure = new RuntimeException('caller failed');
        $caught = null;

        try {
            (new BoundedLockWait(DB::connection()))->enrollment(3, function () use ($failure): never {
                expect(boundedWaitCurrentMs())->toBe(3_000);

                throw $failure;
            });
        } catch (RuntimeException $exception) {
            $caught = $exception;
        }

        expect($caught)->toBe($failure)
            ->and(boundedWaitCurrentMs())->toBe(47_000);
    });
});

it('restores the prior value when a database query throws', function (): void {
    withParkedBoundedWait(function (): void {
        $failure = new QueryException(
            DB::connection()->getName() ?? 'default',
            'select deliberately_missing_column',
            [],
            new PDOException('unrelated query failure'),
        );
        $caught = null;

        try {
            (new BoundedLockWait(DB::connection()))->enrollment(3, function () use ($failure): never {
                expect(boundedWaitCurrentMs())->toBe(3_000);

                throw $failure;
            });
        } catch (QueryException $exception) {
            $caught = $exception;
        }

        expect($caught)->toBe($failure)
            ->and(boundedWaitCurrentMs())->toBe(47_000);
    });
});

it('restores nested scopes to the immediate prior bound', function (): void {
    withParkedBoundedWait(function (): void {
        $primitive = new BoundedLockWait(DB::connection());

        $primitive->enrollment(1, function () use ($primitive): void {
            expect(boundedWaitCurrentMs())->toBe(1_000);

            $primitive->enrollment(5, function (): void {
                expect(boundedWaitCurrentMs())->toBe(5_000);
            });

            expect(boundedWaitCurrentMs())->toBe(1_000);
        });

        expect(boundedWaitCurrentMs())->toBe(47_000);
    });
});

it('rejects an unbounded or fail-immediately value', function (int $seconds): void {
    (new BoundedLockWait(DB::connection()))->enrollment($seconds, fn (): bool => true);
})->with(['zero' => [0], 'negative' => [-1]])
    ->throws(InvalidArgumentException::class, 'at least one second');

it('fixes the shared-dimension budget at one second with no duration input', function (): void {
    withParkedBoundedWait(function (): void {
        (new BoundedLockWait(DB::connection()))->shared(function (): void {
            expect(boundedWaitCurrentMs())->toBe(1_000);
        });

        expect(boundedWaitCurrentMs())->toBe(47_000);
    });
});

it('names the unsupported driver before opening a connection', function (): void {
    $connection = new Connection(
        static function (): PDO {
            throw new RuntimeException('The unsupported-driver test must not open a PDO connection.');
        },
        config: ['driver' => 'oracle'],
    );

    expect(fn (): mixed => (new BoundedLockWait($connection))->shared(fn (): bool => true))
        ->toThrow(InvalidArgumentException::class, 'driver "oracle"');
});
