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
