<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests;

use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Application;
use InvalidArgumentException;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [VouchServiceProvider::class];
    }

    /**
     * The connection is chosen by environment so one suite runs on three
     * engines. The adversarial contention matrix additionally requires a
     * FILE-backed SQLite path: each connection to an in-memory SQLite database
     * gets its own private database, so two "competing" connections would never
     * actually contend.
     *
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $connection = (string) (getenv('VOUCH_TEST_DB') ?: 'sqlite');

        $app['config']->set('database.default', $connection);
        $app['config']->set('app.timezone', 'UTC');

        /*
         * A fixed key, so encrypted casts behave reproducibly across runs.
         * Required by AuthCredential::$secret, AuthConnection::$client_secret,
         * and SessionBinding's HMAC — all of which fail loudly without it,
         * which is the correct behaviour and worth preserving in production.
         */
        $app['config']->set('app.key', 'base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');

        match ($connection) {
            'sqlite' => $app['config']->set('database.connections.sqlite', [
                'driver' => 'sqlite',
                'database' => getenv('VOUCH_SQLITE_PATH') ?: ':memory:',
                'prefix' => '',
                'foreign_key_constraints' => true,
                /*
                 * Contention tests need a writer to WAIT for the lock rather
                 * than fail instantly. SQLite's default busy timeout is 0.
                 */
                'busy_timeout' => 5000,

                /*
                 * journal_mode is deliberately NOT set here, and this is not an
                 * oversight — it was tried and it broke the contention suite.
                 *
                 * Laravel's SQLite connector issues `pragma journal_mode = ...`
                 * on EVERY new connection, and switching journal mode needs a
                 * brief exclusive lock. The contention tests open several
                 * connections to one file precisely so that one of them holds a
                 * lock, so the later connections' pragma fails outright with
                 * SQLITE_BUSY before any test body runs.
                 *
                 * It hid for several tasks because the default database here is
                 * `:memory:`, where the whole contention suite skips itself —
                 * so the regression was only reachable with VOUCH_SQLITE_PATH
                 * set to a file, which is exactly the configuration CI uses.
                 *
                 * The serialization these tests prove does not need WAL: it
                 * comes from SQLite's database-level write lock plus the
                 * busy_timeout above.
                 */
            ]),
            'mysql' => $app['config']->set('database.connections.mysql', [
                'driver' => 'mysql',
                'host' => getenv('DB_HOST') ?: '127.0.0.1',
                'port' => getenv('DB_PORT') ?: '3306',
                'database' => getenv('DB_DATABASE') ?: 'vouch_test',
                'username' => getenv('DB_USERNAME') ?: 'root',
                'password' => getenv('DB_PASSWORD') ?: 'password',
                'charset' => 'utf8mb4',
                'prefix' => '',
            ]),
            'pgsql' => $app['config']->set('database.connections.pgsql', [
                'driver' => 'pgsql',
                'host' => getenv('DB_HOST') ?: '127.0.0.1',
                'port' => getenv('DB_PORT') ?: '5432',
                'database' => getenv('DB_DATABASE') ?: 'vouch_test',
                'username' => getenv('DB_USERNAME') ?: 'postgres',
                'password' => getenv('DB_PASSWORD') ?: 'password',
                'charset' => 'utf8',
                'prefix' => '',
            ]),
            default => throw new InvalidArgumentException(
                sprintf('Unsupported VOUCH_TEST_DB value: %s', $connection),
            ),
        };
    }
}
