<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use DateTimeImmutable;
use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\IssuanceRefused;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenGrant;
use Fissible\Vouch\Vouch;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Laravel\Sanctum\SanctumServiceProvider;
use PDO;
use PHPUnit\Framework\Attributes\Test;
use Throwable;

/**
 * Issue #33 — the credential liveness recheck must read what is committed.
 *
 * `Vouch::issueToken()` locks the proof's credentials, re-reads the session
 * proof under `lockForUpdate`, and then rechecks liveness with an ORDINARY
 * select. Under REPEATABLE READ that last read is answered from the
 * transaction's snapshot, established by an earlier statement — before the lock
 * wait. A credential disabled while issuance waited is therefore invisible to
 * it, while the locking read three lines above sees the latest committed row.
 * One transaction, two views of the same table.
 *
 * The consequence is durable rather than transient: the disabling mutation
 * serialized first, so its assurance withdrawal has already run and will not
 * run again. Issuance then mints an assured token citing a dead credential, and
 * nothing afterwards withdraws it.
 *
 * WHY THE INTERLEAVING IS SHAPED THIS WAY. The defect lives in a snapshot, and
 * a snapshot belongs to a transaction. A test that lets issuance time out, roll
 * back and retry in a NEW transaction gets a new snapshot and sees the disable
 * — passing against the broken code. So the caller's transaction is opened
 * first, made to read (which is what fixes the snapshot), and kept open across
 * the concurrent commit. `issueToken()` refuses outright without an active
 * caller transaction, so this is also the ordinary way a host calls it.
 */
final class CredentialLivenessSnapshotTest extends TestCase
{
    use DatabaseMigrations;
    use UsesSanctumSchema;

    /** @return list<class-string> */
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
            'document' => ['all_of' => ['password', 'totp']],
            'posture' => 'friendly',
        ]);
    }

    /**
     * A connection this test owns, able to COMMIT while the caller's
     * transaction is still open.
     *
     * Laravel's own connection is inside that transaction, so a disable issued
     * through it would be part of the very transaction whose view is under
     * test — it would be visible for the wrong reason and prove nothing.
     */
    private function independentPdo(): PDO
    {
        $host = getenv('DB_HOST') ?: '127.0.0.1';
        $port = getenv('DB_PORT') ?: '3306';
        $database = getenv('DB_DATABASE') ?: 'vouch_test';
        $username = getenv('DB_USERNAME') ?: 'root';
        $password = getenv('DB_PASSWORD') ?: 'password';

        return new PDO(
            "mysql:host={$host};port={$port};dbname={$database}",
            $username,
            (string) $password,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
        );
    }

    private function establishSession(): AuthCredential
    {
        app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)
            ->enroll(7, ['password' => 'correct horse battery staple']);
        app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
            ->enroll(7, ['label' => 'ada@acme.example']);

        $password = AuthCredential::query()->where('user_id', 7)->where('type', 'password')->firstOrFail();
        $totp = AuthCredential::query()->where('user_id', 7)->where('type', 'totp')->firstOrFail();

        $factors = [
            new SatisfiedFactor('password', (string) $password->id, FactorKind::Knowledge, FactorStrength::Knowledge, false, false, false, null, new DateTimeImmutable('2026-09-12T10:00:00+00:00')),
            new SatisfiedFactor('totp', (string) $totp->id, FactorKind::Possession, FactorStrength::Possession, false, false, false, null, new DateTimeImmutable('2026-09-12T10:05:00+00:00')),
        ];

        $this->actingAs(TokenUser::query()->findOrFail(7));
        session()->start();

        app(SessionLifecycle::class)->establish(
            new AuthSuccess(7, $factors, AssuranceFacts::fromFactors($factors), 'ignored', 'ignored', null),
        );

        return $totp;
    }

    #[Test]
    public function issuance_refuses_a_credential_disabled_after_the_callers_snapshot(): void
    {
        /*
         * Named for what this actually exercises. The competing disable commits
         * BEFORE issueToken() is called, so there is no lock wait here and no
         * credential-mutation facade runs: what is reproduced is the stale
         * snapshot a committed disable leaves behind. The assurance withdrawal
         * having already run is the production consequence being modelled, not
         * something this test observes.
         *
         * Skipped off MySQL rather than run vacuously. PostgreSQL's READ
         * COMMITTED takes a fresh snapshot per statement, so the recheck is
         * already correct there; under PostgreSQL REPEATABLE READ the existing
         * credential lock acquisition would raise a serialization failure
         * instead, which is a different outcome needing its own assertion.
         * SQLite is skipped because this exact schedule is not constructible
         * there, not because its statements refresh a snapshot -- they do not.
         */
        if (DB::getDriverName() !== 'mysql') {
            self::markTestSkipped('This schedule needs MySQL REPEATABLE READ; other engines reach the same guarantee by other means.');
        }

        $totp = $this->establishSession();
        $grant = new TokenGrant(
            subject: SubjectKey::of((new TokenUser())->getMorphClass(), 7),
            name: 'api',
            abilities: ['orders:read'],
        );

        /*
         * PIN THE ISOLATION LEVEL. Checking the driver name does not establish
         * REPEATABLE READ -- a MySQL configured for READ COMMITTED would let
         * broken code pass this test, and the premise would be silently false.
         */
        DB::statement('set transaction isolation level repeatable read');
        DB::beginTransaction();

        try {
            // The statement that fixes the snapshot. A host doing any read
            // before issuing gets this for free, which is why the defect is
            // reachable rather than theoretical.
            DB::table('auth_credentials')->where('user_id', 7)->count();

            // Caller-owned data, to prove issuance did not roll the caller's
            // transaction back and start a new one. Transaction depth cannot
            // show that: rollback followed by begin restores the same depth.
            DB::table('auth_policies')->insert([
                'tenant_id' => null,
                'scope' => 'caller-sentinel',
                'document' => json_encode(['all_of' => ['password']], JSON_THROW_ON_ERROR),
                'posture' => 'friendly',
            ]);

            $pdo = $this->independentPdo();
            $statement = $pdo->prepare('update auth_credentials set disabled_at = now() where id = ? and disabled_at is null');
            $statement->execute([$totp->id]);

            self::assertSame(1, $statement->rowCount(), 'The competing disable did not affect the credential under test.');

            /*
             * The precondition, asserted rather than assumed: the caller's
             * transaction must still see this credential as live. If it does
             * not, the snapshot is not stale and the test proves nothing about
             * the defect.
             */
            self::assertNull(
                DB::table('auth_credentials')->where('id', $totp->id)->value('disabled_at'),
                'The caller already sees the disable, so this run does not exercise a stale snapshot.',
            );

            $refusal = null;

            try {
                Vouch::issueToken($grant);
            } catch (Throwable $thrown) {
                $refusal = $thrown;
            }

            self::assertInstanceOf(
                IssuanceRefused::class,
                $refusal,
                'Issuance accepted a credential that was already disabled and committed.',
            );

            // Nothing was written before the refusal. A mint-then-throw
            // implementation would otherwise hide behind the cleanup rollback.
            self::assertSame(0, (int) DB::table('personal_access_tokens')->count());
            self::assertSame(0, (int) DB::table('auth_token_assurances')->count());
            self::assertSame(0, (int) DB::table('auth_token_credentials')->count());

            // And the caller's transaction is the one it opened.
            self::assertSame(
                1,
                (int) DB::table('auth_policies')->where('scope', 'caller-sentinel')->count(),
                'Issuance replaced the caller transaction, which would give it a fresh snapshot and hide the defect.',
            );
        } finally {
            DB::rollBack();

            $pdo = $this->independentPdo();
            $pdo->prepare('update auth_credentials set disabled_at = null where id = ?')->execute([$totp->id]);
        }
    }

    #[Test]
    public function issuance_still_succeeds_when_no_credential_was_disabled(): void
    {
        /*
         * The paired positive, and it runs on EVERY engine: the negative is
         * MySQL-only because the defect is only observable there, but the fix
         * has to be correct everywhere, and this is the test that says so.
         *
         * It excludes a recheck changed to refuse unconditionally. It does not
         * exclude a deadlocking one -- an earlier comment claimed it did, which
         * was wrong: a raw deadlock exception fails the negative's
         * assertInstanceOf outright rather than satisfying it. Lock ordering
         * and contention have their own coverage elsewhere.
         */
        $this->establishSession();
        $grant = new TokenGrant(
            subject: SubjectKey::of((new TokenUser())->getMorphClass(), 7),
            name: 'api',
            abilities: ['orders:read'],
        );

        DB::beginTransaction();

        try {
            DB::table('auth_credentials')->where('user_id', 7)->count();

            $issued = Vouch::issueToken($grant);

            self::assertNotSame('', $issued->plainText);
        } finally {
            DB::rollBack();
        }
    }
}
