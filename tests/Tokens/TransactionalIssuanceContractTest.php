<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\Drivers\SanctumTokenIssuer;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenGrant;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Fissible\Vouch\Tokens\TokenIssuerRegistry;
use Illuminate\Support\Facades\Schema;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 1 — THE GATE.
 *
 * The addendum's §1 makes transaction ownership structural rather than
 * advisory, and this is the test that does the making. `issue()` must perform
 * every persistent effect through the connection it was handed, so that a
 * failure anywhere in the issuing transaction leaves no token behind.
 *
 * The failure it prevents is specific and bad: a usable Sanctum token with no
 * assurance record. The obvious implementation — `$user->createToken()` —
 * produces exactly that, because it resolves the model's DEFAULT connection and
 * commits outside the caller's transaction.
 *
 * Two things make this test discriminating rather than decorative. It rolls back
 * the OUTER transaction AFTER `issue()` has returned, so a driver cannot pass by
 * merely deferring its commit. And it asserts that EVERY driver-owned row is
 * gone rather than only the token row, so a side write cannot survive unnoticed.
 */
final class TransactionalIssuanceContractTest extends TestCase
{
    use DatabaseMigrations;
    use UsesSanctumSchema;

    /**
     * @return list<class-string>
     */
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

        if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
            && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
            $this->markTestSkipped(
                'A distinct connection needs a shared database. In-memory SQLite gives each '
                . 'connection its own, so a rollback here would prove nothing.',
            );
        }

        $this->createTokenSubjectTables();

        Config::set(
            'database.connections.issuing',
            Config::array('database.connections.' . Config::string('database.default')),
        );
    }

    private function grant(int $subjectId = 7): TokenGrant
    {
        $user = TokenUser::query()->create(['id' => $subjectId, 'name' => 'ada']);

        return new TokenGrant(
            subject: SubjectKey::of($user->getMorphClass(), $user->getKey()),
            name: 'rollback-probe',
            abilities: ['deploy:write'],
            actor: ActorKind::Human,
        );
    }

    /**
     * A row census of EVERY table, taken through a connection that did not
     * participate in the rolled-back transaction.
     *
     * Naming the two tables we expect would let a side write to any third table
     * survive unnoticed, and reading through the rolled-back connection would
     * hide a row the driver committed on a connection of its own. Both of those
     * are precisely the escapes this gate exists to catch, so the census is
     * total and the reader is independent.
     *
     * WHAT IT DETECTS, stated honestly: rows added or removed anywhere. It does
     * NOT detect an in-place UPDATE that preserves cardinality, so the gate's
     * claim is "the issuer left no row behind", not "nothing anywhere changed".
     * An earlier draft asserted the stronger sentence, which the mechanism does
     * not support.
     *
     * @return array<string, int>
     */
    private function censusFromIndependentConnection(): array
    {
        $counts = [];

        foreach (Schema::getTableListing() as $table) {
            $name = str_contains($table, '.') ? substr((string) strrchr($table, '.'), 1) : $table;

            if (in_array($name, ['migrations', 'sqlite_sequence'], true)) {
                continue;
            }

            $counts[$name] = (int) DB::connection()->table($name)->count();
        }

        return $counts;
    }

    #[Test]
    public function nothing_the_issuer_wrote_survives_a_rollback_of_the_caller_transaction(): void
    {
        $connection = DB::connection('issuing');
        $grant = $this->grant();

        /*
         * BEFORE the transaction opens. An earlier draft snapshotted after
         * issue() returned, which defeated the whole gate: a row the issuer
         * escaped onto the default connection would sit in both censuses and
         * compare equal.
         */
        $before = $this->censusFromIndependentConnection();

        $connection->beginTransaction();
        $issued = app(SanctumTokenIssuer::class)->issue($connection, $grant);

        // Inside the transaction the token is real, which is what makes the
        // rollback below meaningful rather than vacuous.
        self::assertSame(
            1,
            (int) $connection->table('personal_access_tokens')->where('id', (int) $issued->tokenKey)->count(),
        );

        $connection->rollBack();

        // No row was added or removed anywhere — see the census docblock for
        // what that does and does not establish.
        self::assertSame($before, $this->censusFromIndependentConnection());
        self::assertSame(0, (int) DB::connection()->table('personal_access_tokens')->count());
    }

    #[Test]
    public function the_gate_applies_to_every_registered_issuer_not_only_sanctum(): void
    {
        /*
         * The guarantee belongs to the CONTRACT, so the census runs against
         * each issuer that claims transactional support. A future driver
         * inherits this rather than being trusted, which is the difference
         * between a contract and a convention.
         */
        $issuers = app(TokenIssuerRegistry::class)->transactionalIssuers();

        // An empty list would make the loop below vacuously green.
        $keys = array_map(static fn ($issuer): string => $issuer->issuerKey(), $issuers);
        self::assertContains('sanctum', $keys);

        $subjectId = 100;

        foreach ($issuers as $issuer) {
            $connection = DB::connection('issuing');
            // A distinct subject per issuer, so a second transactional driver
            // does not collide on the primary key of the first one's user.
            $grant = $this->grant(++$subjectId);

            $before = $this->censusFromIndependentConnection();

            $connection->beginTransaction();
            $issuer->issue($connection, $grant);
            $connection->rollBack();

            self::assertSame(
                $before,
                $this->censusFromIndependentConnection(),
                sprintf('Issuer "%s" left something behind after rollback.', $issuer->issuerKey()),
            );
        }
    }

    #[Test]
    public function the_token_is_also_gone_from_a_separate_connection_after_rollback(): void
    {
        /*
         * Read back through a DIFFERENT connection, because a driver that wrote
         * on its own connection would still show zero rows when queried through
         * the rolled-back one — the row would be committed and simply invisible
         * to a reader that never saw it. This is the assertion that actually
         * catches `$user->createToken()`.
         */
        $connection = DB::connection('issuing');
        $grant = $this->grant();

        $connection->beginTransaction();
        app(SanctumTokenIssuer::class)->issue($connection, $grant);
        $connection->rollBack();

        self::assertSame(0, (int) DB::connection()->table('personal_access_tokens')->count());
    }

    #[Test]
    public function a_committed_issuance_does_survive(): void
    {
        // The pair for the two above: an implementation that never persisted
        // anything would satisfy both rollback assertions and be useless.
        $connection = DB::connection('issuing');
        $grant = $this->grant();

        $connection->beginTransaction();
        $issued = app(SanctumTokenIssuer::class)->issue($connection, $grant);
        $connection->commit();

        self::assertSame(
            1,
            (int) DB::connection()->table('personal_access_tokens')->where('id', (int) $issued->tokenKey)->count(),
        );
    }
}
