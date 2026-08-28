<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use InvalidArgumentException;
use RuntimeException;
use Throwable;

/**
 * Applies a connection-local database lock-wait bound for one critical section.
 *
 * The prior value is captured per invocation and restored in finally. That is
 * deliberately stronger than restoring an engine default: connections belong
 * to the host, and nested callers must restore their immediate caller's bound.
 */
final readonly class BoundedLockWait
{
    public function __construct(private Connection $connection) {}

    /**
     * Enrollment has its own host-configured wait budget.
     *
     * @template TResult
     *
     * @param  callable(): TResult  $critical
     * @return TResult
     */
    public function enrollment(int $seconds, callable $critical): mixed
    {
        return $this->within($seconds, $critical);
    }

    /**
     * Shared throttle dimensions are advisory and must not park a request
     * behind a high-blast-radius bucket for more than one second. There is no
     * duration parameter by design, so this budget cannot become host config.
     *
     * @template TResult
     *
     * @param  callable(): TResult  $critical
     * @return TResult
     */
    public function shared(callable $critical): mixed
    {
        return $this->within(1, $critical);
    }

    /**
     * @template TResult
     *
     * @param  callable(): TResult  $critical
     * @return TResult
     */
    private function within(int $seconds, callable $critical): mixed
    {
        if ($seconds < 1) {
            throw new InvalidArgumentException('A database lock-wait bound must be at least one second.');
        }

        $prior = $this->read();
        $this->writeSeconds($seconds);
        $failure = null;

        try {
            return $critical();
        } catch (Throwable $exception) {
            $failure = $exception;

            throw $exception;
        } finally {
            try {
                $this->restore($prior);
            } catch (QueryException $restoreFailure) {
                if (! $this->restoresOnRollback($failure, $restoreFailure)) {
                    throw $restoreFailure;
                }
            }
        }
    }

    /** @return int|string */
    private function read(): int|string
    {
        $value = match ($this->connection->getDriverName()) {
            'mysql' => $this->connection->scalar('SELECT @@SESSION.innodb_lock_wait_timeout'),
            'pgsql' => $this->connection->scalar('SHOW lock_timeout'),
            'sqlite' => $this->connection->scalar('PRAGMA busy_timeout'),
            default => throw new InvalidArgumentException(
                'Vouch cannot bound database lock waits for driver "'
                . $this->connection->getDriverName()
                . '". Add measured set, readback, and restoration semantics for it first.',
            ),
        };

        if (! is_int($value) && ! is_string($value)) {
            throw new RuntimeException('The database returned a non-scalar lock-wait setting.');
        }

        return $value;
    }

    private function writeSeconds(int $seconds): void
    {
        match ($this->connection->getDriverName()) {
            'mysql' => $this->connection->statement(
                sprintf('SET SESSION innodb_lock_wait_timeout = %d', $seconds),
            ),
            'pgsql' => $this->setPostgres($seconds . 's'),
            'sqlite' => $this->connection->statement(
                sprintf('PRAGMA busy_timeout = %d', $seconds * 1000),
            ),
            default => throw new InvalidArgumentException('Unsupported database driver.'),
        };
    }

    /** @param int|string $prior */
    private function restore(int|string $prior): void
    {
        match ($this->connection->getDriverName()) {
            'mysql' => $this->connection->statement(
                sprintf('SET SESSION innodb_lock_wait_timeout = %d', (int) $prior),
            ),
            'pgsql' => $this->setPostgres((string) $prior),
            'sqlite' => $this->connection->statement(
                sprintf('PRAGMA busy_timeout = %d', (int) $prior),
            ),
            default => throw new InvalidArgumentException('Unsupported database driver.'),
        };
    }

    private function setPostgres(string $value): void
    {
        $this->connection->scalar(
            "SELECT set_config('lock_timeout', ?, ?)",
            [$value, $this->connection->transactionLevel() > 0],
        );
    }

    /**
     * A PostgreSQL statement error aborts its transaction, so no restoration
     * statement can run before rollback: it fails with 25P02 and would mask the
     * contention that caused it. The original QueryException may be wrapped by
     * the critical section before finally runs (EnrollmentGuard turns a verified
     * acquisition timeout into EnrollmentRefused), so inspect its exception
     * chain rather than exposing the restoration failure in the wrong direction.
     * The setting is transaction-local in this case, so rollback itself restores
     * the captured session value. No other restore failure is suppressed.
     */
    private function restoresOnRollback(?Throwable $failure, QueryException $restoreFailure): bool
    {
        if ($this->connection->getDriverName() !== 'pgsql'
            || $this->connection->transactionLevel() === 0
            || $restoreFailure->getCode() !== '25P02') {
            return false;
        }

        while ($failure instanceof Throwable) {
            if ($failure instanceof QueryException) {
                return true;
            }

            $failure = $failure->getPrevious();
        }

        return false;
    }
}
