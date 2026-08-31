<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Concurrency;

use DateTimeImmutable;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Fissible\Vouch\Support\LockContention;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenGrant;
use Fissible\Vouch\Vouch;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Laravel\Sanctum\SanctumServiceProvider;
use PDOException;
use PHPUnit\Framework\Attributes\Test;
use Throwable;

/**
 * 2.4 Task 5a — the guarantee the subject anchor MUST NOT quietly drop.
 *
 * Vouch::issueToken re-validates the session after acquiring locks, and says so:
 *
 *     // The locks make this read durable. The first validation is advisory:
 *     // a session can be revoked after it and before lock acquisition.
 *
 * That durability was supplied INCIDENTALLY, by the old lockSubject() taking a
 * FOR UPDATE on auth_sessions. Replacing it with a subject anchor removes the
 * session row from the lock set, and nothing in the 5a freeze noticed: every
 * test asserted what the anchor DOES, and none asserted what the thing it
 * replaced was holding.
 *
 * The window is small and the consequence is not — a revocation committing
 * between the re-validation and the issuance commit yields a live, fully
 * assured token minted against a session that was revoked first.
 *
 * The old lock was also weaker than its own comment claimed: it took
 * `auth_sessions where user_id = ?` and `->first()`, an arbitrary row for that
 * user, while the re-validation reads the session by `session_binding`. With
 * more than one session it could lock a different row than the one it was
 * making durable. So this pins the BEHAVIOUR rather than either implementation:
 * a concurrent revocation of the re-validated session must not slip through.
 */
final class IssuanceSessionDurabilityTest extends TestCase
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

        // Issuance refuses a proof that satisfies no policy, so the fixture
        // needs one the established session actually meets.
        AuthPolicy::query()->create([
            'tenant_id' => null,
            'scope' => 'token_issue',
            'document' => ['all_of' => ['password']],
            'posture' => 'friendly',
        ]);

        // A second name over ONE database, so its transaction is genuinely
        // invisible to the default connection. Copied from the default rather
        // than invented, so the matrix points it at the engine under test.
        Config::set(
            'database.connections.revoker',
            Config::array('database.connections.' . Config::string('database.default')),
        );

        if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
            && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
            $this->markTestSkipped(
                'Contention tests need a shared database. In-memory SQLite gives each connection '
                . 'its own, so this would pass without racing.',
            );
        }
    }

    #[Test]
    public function it_holds_the_revalidated_session_against_a_concurrent_revocation(): void
    {
        app(PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
        $credential = AuthCredential::query()->where('user_id', 7)->where('type', 'password')->firstOrFail();

        session()->start();
        $this->actingAs(TokenUser::query()->findOrFail(7));
        $factors = [new SatisfiedFactor('password', (string) $credential->id, FactorKind::Knowledge,
            FactorStrength::Knowledge, false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'))];
        app(SessionLifecycle::class)->establish(
            new AuthSuccess(7, $factors, AssuranceFacts::fromFactors($factors), 'ignored', 'ignored'),
        );
        $session = AuthSession::query()->firstOrFail();

        $revoker = DB::connection('revoker');
        $blocked = false;

        DB::beginTransaction();

        try {
            // Acquires the locks and performs the durable re-validation.
            Vouch::issueToken(new TokenGrant(
                SubjectKey::of((new TokenUser)->getMorphClass(), 7),
                'api',
                ['orders:read'],
            ));

            /*
             * A revocation arriving inside the window. It must not commit while
             * issuance holds its locks; if it can, the token about to be
             * committed is bound to an already-revoked session.
             */
            $revoker->beginTransaction();

            try {
                $revoker->statement(match ($revoker->getDriverName()) {
                    'mysql', 'mariadb' => 'SET SESSION innodb_lock_wait_timeout = 1',
                    'pgsql' => "SET LOCAL lock_timeout = '1s'",
                    default => 'SELECT 1',
                });

                $revoker->table('auth_sessions')->where('id', $session->id)->update(['revoked_at' => now()]);
                $revoker->commit();
            } catch (Throwable $exception) {
                try {
                    $revoker->rollBack();
                } catch (Throwable) {
                    // A timed-out PostgreSQL transaction is already aborted.
                }

                $blocked = $this->isContention($revoker->getDriverName(), $exception);

                if (! $blocked) {
                    throw $exception;
                }
            } finally {
                if (in_array($revoker->getDriverName(), ['mysql', 'mariadb'], true)) {
                    $revoker->statement('SET SESSION innodb_lock_wait_timeout = DEFAULT');
                }
            }
        } finally {
            DB::rollBack();
        }

        self::assertTrue($blocked, 'A concurrent revocation committed while issuance held its locks.');
    }

    /** Only a driver-verified lock condition counts; everything else is a real failure. */
    private function isContention(string $driver, Throwable $exception): bool
    {
        if ($exception instanceof QueryException) {
            return (new LockContention())->isVerified(DB::connection('revoker'), $exception);
        }

        return $driver === 'sqlite'
            && $exception instanceof PDOException
            && ($exception->getCode() === 5 || ($exception->errorInfo[1] ?? null) === 5);
    }
}
