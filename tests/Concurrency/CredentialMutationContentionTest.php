<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Concurrency;

use DateTimeImmutable;
use Fissible\Vouch\Credentials\CredentialMutation;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Fissible\Vouch\Support\LockContention;
use Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\CredentialLockManager;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Tokens\TokenGrant;
use Fissible\Vouch\Tokens\TokenIssuerRegistry;
use Fissible\Vouch\Vouch;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Database\Connection;
use Laravel\Sanctum\SanctumServiceProvider;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PDOException;
use PHPUnit\Framework\Attributes\Test;
use Throwable;

/**
 * 2.4 Task 5b — the gate: issuance and subject-wide revocation cannot interleave.
 *
 * The dangerous ordering is the one that leaves a token behind. Revocation
 * sweeps a subject's tokens; issuance mints a new one. If they can overlap, an
 * issuance that began before the sweep can commit AFTER it, producing a live
 * assurance-bound token for a subject whose credentials were just changed —
 * exactly the token the sweep existed to remove, and with no record that it
 * escaped.
 *
 * Both protocols acquire the same subject anchor from Task 5a, which is what
 * makes that impossible. Proven by interleaving real connections rather than by
 * reading the code, because the claim is about a database.
 */
final class CredentialMutationContentionTest extends TestCase
{
    use DatabaseMigrations;
    use UsesSanctumSchema;

    /** @return array<int, class-string> */
    protected function getPackageProviders($app): array
    {
        return [SanctumServiceProvider::class, VouchServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('auth.providers.users.model', TokenUser::class);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->createTokenSubjectTables();
        TokenUser::query()->create(['id' => 7, 'name' => 'ada']);
        AuthPolicy::query()->create([
            'tenant_id' => null,
            'scope' => 'token_issue',
            'document' => ['all_of' => ['password']],
            'posture' => 'friendly',
        ]);

        $settings = Config::array('database.connections.' . Config::string('database.default'));

        foreach (['mutation_a', 'mutation_b'] as $name) {
            Config::set('database.connections.' . $name, $settings);
        }

        if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
            && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
            $this->markTestSkipped(
                'Contention tests need a shared database. In-memory SQLite gives each connection '
                . 'its own, so these would pass without racing.',
            );
        }
    }

    private function subject(): SubjectKey
    {
        return SubjectKey::of((new TokenUser)->getMorphClass(), '7');
    }

    /**
     * A live session that real issuance can draw authority from.
     *
     * Vouch::issueToken resolves the session from the host's authentication
     * rather than from a row, so this establishes both.
     */
    private function establishSession(): void
    {
        app(PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
        $credential = AuthCredential::query()->where('user_id', 7)->where('type', 'password')->firstOrFail();

        session()->start();
        $this->actingAs(TokenUser::query()->findOrFail(7));
        $factors = [new SatisfiedFactor('password', stringValue($credential->id), FactorKind::Knowledge,
            FactorStrength::Knowledge, false, false, false, null,
            new DateTimeImmutable('2026-08-13T10:00:00+00:00'))];

        app(SessionLifecycle::class)->establish(
            new AuthSuccess(7, $factors, AssuranceFacts::fromFactors($factors), 'ignored', 'ignored'),
        );
    }

    /** Real issuance on a given connection, as Vouch's public API performs it. */
    private function issueOn(Connection $connection): void
    {
        Vouch::issueToken(new TokenGrant($this->subject(), 'api', ['orders:read']), $connection);
    }

    private function tokenCiting(string $tokenKey, string $credentialId): void
    {
        app(TokenAssuranceRecord::class)->store(
            'sanctum', $tokenKey, $this->subject(), null, ActorKind::Human,
            [new SatisfiedFactor('password', $credentialId, FactorKind::Knowledge, FactorStrength::Knowledge,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'))],
        );
    }

    /**
     * Report whether $work on $connection was BLOCKED by another holder.
     *
     * Only a driver-verified lock condition counts; anything else is a real
     * failure and is rethrown. The SQLite branch mirrors
     * DatabaseRowLockContentionTest: SQLite surfaces a bounded write failure as
     * PDOException code 5 at COMMIT rather than as a QueryException.
     */
    private function blocked(Connection $connection, callable $work): bool
    {
        $connection->beginTransaction();

        try {
            // Inside the transaction: PostgreSQL's SET LOCAL is a silent no-op
            // outside one, which would leave this on an unbounded wait and hang
            // CI rather than fail it.
            $connection->statement(match ($connection->getDriverName()) {
                'mysql', 'mariadb' => 'SET SESSION innodb_lock_wait_timeout = 1',
                'pgsql' => "SET LOCAL lock_timeout = '1s'",
                default => 'SELECT 1',
            });

            $work($connection);
            $connection->commit();

            return false;
        } catch (Throwable $exception) {
            try {
                $connection->rollBack();
            } catch (Throwable) {
                // A timed-out PostgreSQL transaction is already aborted.
            }

            if ($exception instanceof QueryException) {
                if (! (new LockContention())->isVerified($connection, $exception)) {
                    throw $exception;
                }

                return true;
            }

            if ($connection->getDriverName() === 'sqlite'
                && $exception instanceof PDOException
                && ($exception->getCode() === 5 || ($exception->errorInfo[1] ?? null) === 5)) {
                return true;
            }

            throw $exception;
        } finally {
            if (in_array($connection->getDriverName(), ['mysql', 'mariadb'], true)) {
                $connection->statement('SET SESSION innodb_lock_wait_timeout = DEFAULT');
            }
        }
    }

    /**
     * Report whether $work was BLOCKED, WITHOUT opening a transaction first.
     *
     * The facade owns its transaction — it refuses to run inside a caller's,
     * because joining one would leave Vouch's invalidation uncommitted when the
     * driver's revoke() is called, which is the ordering the whole protocol
     * rests on. So a probe that wrapped the call could not exercise the real
     * entry path at all.
     *
     * PostgreSQL's bound is therefore SET (session), not SET LOCAL, which
     * applies only inside a transaction and would silently be a no-op here.
     */
    private function blockedTopLevel(Connection $connection, callable $work): bool
    {
        $connection->statement(match ($connection->getDriverName()) {
            'mysql', 'mariadb' => 'SET SESSION innodb_lock_wait_timeout = 1',
            'pgsql' => "SET lock_timeout = '1s'",
            default => 'SELECT 1',
        });

        try {
            $work($connection);

            return false;
        } catch (Throwable $exception) {
            if ($exception instanceof QueryException) {
                if (! (new LockContention())->isVerified($connection, $exception)) {
                    throw $exception;
                }

                return true;
            }

            if ($connection->getDriverName() === 'sqlite'
                && $exception instanceof PDOException
                && ($exception->getCode() === 5 || ($exception->errorInfo[1] ?? null) === 5)) {
                return true;
            }

            throw $exception;
        } finally {
            $connection->statement(match ($connection->getDriverName()) {
                'mysql', 'mariadb' => 'SET SESSION innodb_lock_wait_timeout = DEFAULT',
                'pgsql' => 'SET lock_timeout = DEFAULT',
                default => 'SELECT 1',
            });
        }
    }

    #[Test]
    public function a_subject_wide_sweep_excludes_a_concurrent_issuance(): void
    {
        /*
         * Driven through the REAL operations, not through CredentialLockManager.
         * Asserting that two direct acquire() calls exclude each other proves
         * the lock works — which Task 5a already proved — and says nothing
         * about whether issuance and revocation actually take it. A subjectWide()
         * that skipped the lock, or an issuance that stopped taking it, would
         * pass a lock-manager test and still interleave in production.
         *
         * The escape this prevents: an issuance that began before the sweep
         * commits after it, leaving a live assurance-bound token for a subject
         * whose password just changed — the exact token the sweep existed to
         * remove, with nothing recording that it got away.
         */
        $this->establishSession();
        app()->instance(TokenIssuerRegistry::class, new TokenIssuerRegistry([new RecordingIssuer('sanctum')]));

        /*
         * The sweep runs at TOP LEVEL, owning its own transaction as the
         * protocol requires, and the competing issuance is attempted from
         * INSIDE its write closure — the only point at which the sweep's locks
         * are demonstrably held. Wrapping the facade in a transaction of our
         * own would be refused, and would also be asserting a transaction model
         * the contract forbids.
         */
        $wasBlocked = null;

        app()->makeWith(CredentialMutation::class, ['connection' => DB::connection('mutation_a')])
            ->subjectWide($this->subject(), function (Connection $held) use (&$wasBlocked): void {
                $wasBlocked = $this->blocked(DB::connection('mutation_b'), function (Connection $connection): void {
                    $this->issueOn($connection);
                });
            });

        self::assertTrue($wasBlocked);
    }

    #[Test]
    public function a_held_issuance_excludes_a_subject_wide_sweep(): void
    {
        /*
         * The mirror interleaving, and easy to leave untested because it feels
         * like the same test. It is not: a protocol that excluded in only one
         * direction would let a sweep complete while an issuance was in flight,
         * reporting success for a revocation that missed a token committed
         * moments later.
         *
         * The holder acquires through the issuance protocol's own lock manager,
         * and the sweep is driven through the facade.
         */
        $this->establishSession();
        app()->instance(TokenIssuerRegistry::class, new TokenIssuerRegistry([new RecordingIssuer('sanctum')]));

        $issuing = DB::connection('mutation_a');
        $issuing->beginTransaction();
        $this->issueOn($issuing);

        try {
            // Top level: the facade owns its transaction, so this probe must not
            // open one around it.
            $wasBlocked = $this->blockedTopLevel(DB::connection('mutation_b'), function (Connection $connection): void {
                app()->makeWith(CredentialMutation::class, ['connection' => $connection])
                    ->subjectWide($this->subject(), static fn (Connection $inner) => null);
            });
        } finally {
            $issuing->rollBack();
        }

        self::assertTrue($wasBlocked);
    }

    #[Test]
    public function two_different_subjects_mutate_credentials_concurrently(): void
    {
        /*
         * Granularity, without which the protocol is a global write lock on
         * every credential change in the application. Skipped on SQLite, which
         * serializes writers database-wide and so cannot exhibit it — measured
         * during Task 5a, not assumed.
         */
        if (DB::connection('mutation_a')->getDriverName() === 'sqlite') {
            $this->markTestSkipped(
                'SQLite serializes writers database-wide, so per-subject granularity '
                . 'cannot be observed on it. Asserted on the MySQL and PostgreSQL legs.',
            );
        }

        $a = DB::connection('mutation_a');
        $b = DB::connection('mutation_b');

        $a->beginTransaction();
        app(CredentialLockManager::class)->acquire($a, $this->subject(), ['101']);

        try {
            $contended = $this->blocked($b, function (Connection $connection): void {
                app(CredentialLockManager::class)->acquire(
                    $connection,
                    SubjectKey::of(configuredUserProvider(), '8'),
                    ['102'],
                );
            });
        } finally {
            $a->rollBack();
        }

        self::assertFalse($contended);
    }

    #[Test]
    public function the_mutation_facade_serializes_against_a_held_subject(): void
    {
        /*
         * revoking(), the third entry point. The two tests above cover
         * subjectWide() in both directions; this one exists so a facade that
         * locked correctly on the sweep and not on the precise path cannot
         * pass. All three public methods take the subject anchor or none of
         * this holds.
         */
        $this->tokenCiting('existing', '101');
        app()->instance(TokenIssuerRegistry::class, new TokenIssuerRegistry([new RecordingIssuer('sanctum')]));

        $holder = DB::connection('mutation_a');
        $holder->beginTransaction();
        app(CredentialLockManager::class)->acquire($holder, $this->subject(), ['101']);

        try {
            $wasBlocked = $this->blockedTopLevel(DB::connection('mutation_b'), function (Connection $connection): void {
                app()->makeWith(CredentialMutation::class, ['connection' => $connection])
                    ->revoking($this->subject(), ['101'], static fn (Connection $inner) => null);
            });
        } finally {
            $holder->rollBack();
        }

        self::assertTrue($wasBlocked);
    }
}
