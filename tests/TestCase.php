<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests;

use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Queue;
use InvalidArgumentException;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        // OTP delivery is production-async. A queue fake preserves that
        // request boundary while allowing each test to invoke the worker
        // explicitly when it needs to inspect the delivered code.
        Queue::fake();
    }

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
    /**
     * Pin one session across every request in a test.
     *
     * Laravel's test client does NOT carry response cookies between calls, so
     * each request would otherwise get a fresh session — and vouch binds an
     * attempt to its session, so step two of any flow dies on a context
     * mismatch.
     *
     * That failure is silent in the worst way: two flows that both die on
     * context mismatch return IDENTICAL refusals, so an enumeration test
     * comparing them passes while proving nothing. Verified, not assumed.
     *
     * The ID must be 40 alphanumeric characters or Store::setId() discards it
     * and substitutes a random one — also silently. See the body for why the
     * cookie has to be encrypted.
     */
    protected function pinSession(?string $id = null): string
    {
        $id ??= substr(str_repeat('vouchtestsession', 4), 0, 40);

        /*
         * ENCRYPTED, not raw. EncryptCookies is in the web group and decrypts
         * every cookie it is not told to skip, so a raw value fails to
         * decrypt, arrives as null, and StartSession silently issues a fresh
         * ID -- the pin appears to work while every request gets a different
         * session.
         *
         * That failure is invisible in exactly the tests most likely to rely
         * on it. A test asserting a REFUSAL still passes, because a session
         * row that is never found is refused for the wrong reason; only the
         * paired test asserting that a SUFFICIENT session gets through
         * exposes it. withCookie() applies the encryption and value prefix the
         * framework expects.
         */
        $this->withCookie(config()->string('session.cookie'), $id);

        return $id;
    }

    protected function vouchSessionPath(): string
    {
        $path = sys_get_temp_dir() . '/vouch-test-sessions';

        if (! is_dir($path)) {
            mkdir($path, 0777, true);
        }

        return $path;
    }

    protected function defineEnvironment($app): void
    {
        $connection = (string) (getenv('VOUCH_TEST_DB') ?: 'sqlite');

        $app['config']->set('database.default', $connection);
        $app['config']->set('app.timezone', 'UTC');

        /*
         * The array driver, not Testbench's default cookie driver.
         * CookieSessionHandler reads from a bound Request, which does not exist
         * in a unit test, so SessionLifecycle's regenerate() dies with
         * "Attempt to read property cookies on null" before reaching anything
         * under test. The array driver exercises the same Session contract.
         */
        $app['config']->set('session.driver', 'file');
        $app['config']->set('session.files', $this->vouchSessionPath());

        /*
         * A fixed key, so encrypted casts behave reproducibly across runs.
         * Required by AuthCredential::$secret, AuthConnection::$client_secret,
         * and SessionBinding's HMAC — all of which fail loudly without it,
         * which is the correct behaviour and worth preserving in production.
         */
        $app['config']->set('app.key', 'base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');

        /*
         * The lowest cost bcrypt accepts, and the reason is the mutation gate.
         *
         * RecoveryCodeFactor verifies a submitted code against up to ten stored
         * digests, so its covering tests do up to ten real bcrypt rounds each.
         * At the framework default that file's tests cost 35 SECONDS, and a
         * mutation run pays that per mutant -- which is what put the Factors
         * slice beyond any usable timeout.
         *
         * This weakens nothing that is asserted. The cost factor is not part of
         * any behaviour under test: the equalization tests count hasher calls
         * rather than measure elapsed time, precisely so they do not depend on
         * how expensive a round is, and bcrypt verifies a digest at any cost it
         * was written with. Production cost stays with the host application,
         * which is where that decision belongs.
         */
        $app['config']->set('hashing.bcrypt.rounds', 4);

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
