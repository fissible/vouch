<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use Fissible\Vouch\Contracts\TokenIssuer;
use Fissible\Vouch\Tests\Support\Tokens\NonTransactionalIssuer;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tokens\TokenIssuerRegistry;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\Drivers\SanctumTokenIssuer;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenGrant;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Laravel\Sanctum\PersonalAccessToken;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;

/**
 * 2.4 Task 1 — the Sanctum driver, against real Sanctum.
 *
 * Every assertion here runs against the installed package rather than a double,
 * because the guarantees being tested are guarantees about Sanctum's actual
 * behaviour: which principal its guard selects, what a TransientToken means, and
 * whether a write lands on the connection Vouch supplied.
 */
final class SanctumIssuerTest extends TestCase
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

        $this->createTokenSubjectTables();

        foreach (['issuer_a'] as $name) {
            Config::set(
                'database.connections.' . $name,
                Config::array('database.connections.' . Config::string('database.default')),
            );
        }
    }

    private function issuer(): SanctumTokenIssuer
    {
        $issuer = app(SanctumTokenIssuer::class);
        self::assertInstanceOf(TokenIssuer::class, $issuer);

        return $issuer;
    }

    private function user(int $id = 7): TokenUser
    {
        return TokenUser::query()->create(['id' => $id, 'name' => 'ada']);
    }

    private function grant(TokenUser $user, ActorKind $actor = ActorKind::Human): TokenGrant
    {
        return new TokenGrant(
            subject: SubjectKey::of($user->getMorphClass(), $user->getKey()),
            name: 'ci',
            abilities: ['deploy:write'],
            actor: $actor,
        );
    }

    #[Test]
    public function it_names_itself_stably(): void
    {
        // issuer_key is persisted alongside every assurance record, so it is an
        // identity, not a label. Renaming it orphans every existing record.
        self::assertSame('sanctum', $this->issuer()->issuerKey());
    }

    #[Test]
    public function it_supports_transactional_issuance(): void
    {
        self::assertTrue($this->issuer()->supportsTransactionalIssuance());
    }

    #[Test]
    public function it_writes_the_token_on_the_supplied_connection(): void
    {
        /*
         * The whole point of taking a connection. `$user->createToken()`
         * resolves the model's DEFAULT connection and would silently escape
         * Vouch's transaction, which is why the driver may not call it.
         */
        $user = $this->user();
        $connection = DB::connection('issuer_a');

        $issued = $this->issuer()->issue($connection, $this->grant($user));

        self::assertSame(
            1,
            $connection->table('personal_access_tokens')->where('id', (int) $issued->tokenKey)->count(),
        );
    }

    #[Test]
    public function it_returns_the_canonical_decimal_token_key(): void
    {
        $issued = $this->issuer()->issue(DB::connection('issuer_a'), $this->grant($this->user()));

        $row = DB::connection('issuer_a')->table('personal_access_tokens')->first();

        self::assertNotNull($row);
        self::assertSame((string) $row->id, $issued->tokenKey);
        self::assertMatchesRegularExpression('/^[0-9]+$/', $issued->tokenKey);
    }

    #[Test]
    public function the_plaintext_it_returns_actually_authenticates(): void
    {
        // A plaintext that does not resolve back to its own row is a token
        // nobody can use, and no other assertion here would notice.
        $issued = $this->issuer()->issue(DB::connection('issuer_a'), $this->grant($this->user()));

        $found = PersonalAccessToken::findToken($issued->plainText);

        self::assertNotNull($found);
        self::assertSame((int) $issued->tokenKey, $found->getKey());
    }

    #[Test]
    public function it_persists_the_host_authorized_abilities_unaltered(): void
    {
        $issued = $this->issuer()->issue(DB::connection('issuer_a'), $this->grant($this->user()));

        $found = PersonalAccessToken::findToken($issued->plainText);

        self::assertNotNull($found);
        self::assertTrue($found->can('deploy:write'));
        self::assertFalse($found->can('something:else'));
    }

    #[Test]
    public function it_binds_the_token_to_the_granted_subject(): void
    {
        $user = $this->user();
        $issued = $this->issuer()->issue(DB::connection('issuer_a'), $this->grant($user));

        self::assertTrue($issued->subject->equals(SubjectKey::of($user->getMorphClass(), $user->getKey())));
    }

    #[Test]
    public function the_registry_refuses_a_non_transactional_issuer_for_human_issuance(): void
    {
        /*
         * The refusal is the contract, so it is tested through the component
         * that enforces it rather than by calling the double directly — a
         * driver that merely reports supportsTransactionalIssuance() === false
         * proves nothing unless something acts on the answer.
         *
         * Refused, never downgraded: silently issuing a human token without the
         * atomicity guarantee is exactly the outcome the guarantee exists to
         * prevent.
         */
        $registry = new TokenIssuerRegistry([new NonTransactionalIssuer()]);

        expect(fn () => $registry->issue('remote', DB::connection('issuer_a'), $this->grant($this->user())))
            ->toThrow(RuntimeException::class);
    }

    #[Test]
    public function the_registry_allows_a_non_transactional_issuer_for_a_machine_grant(): void
    {
        /*
         * The other half. Machine tokens carry no human assurance record, so
         * there is no atomicity to break — and a registry that refused
         * everything would satisfy the test above while making the distinction
         * meaningless.
         */
        $issuer = new NonTransactionalIssuer();
        $registry = new TokenIssuerRegistry([$issuer]);

        $registry->issue('remote', DB::connection('issuer_a'), $this->grant($this->user(), ActorKind::Machine));

        self::assertTrue($issuer->issued);
    }

    #[Test]
    public function it_revokes_only_the_named_token_and_is_idempotent(): void
    {
        /*
         * Two tokens, deliberately. A revoke that deleted every row would pass
         * a single-token assertion and be catastrophic.
         */
        $user = $this->user();
        $doomed = $this->issuer()->issue(DB::connection('issuer_a'), $this->grant($user));
        $spared = $this->issuer()->issue(DB::connection('issuer_a'), $this->grant($user));

        $this->issuer()->revoke($doomed->tokenKey);
        $this->issuer()->revoke($doomed->tokenKey);

        self::assertNull(PersonalAccessToken::find((int) $doomed->tokenKey));
        self::assertNotNull(PersonalAccessToken::find((int) $spared->tokenKey));
    }

    #[Test]
    public function revoking_a_token_that_never_existed_is_not_an_error(): void
    {
        // Revocation converges. A missing row means the goal is already met.
        $this->issuer()->revoke('999999');

        self::assertSame(0, PersonalAccessToken::query()->count());
    }

    #[Test]
    public function it_writes_no_assurance_record_in_this_task(): void
    {
        // Task 1 builds the issuer only. auth_token_assurances belongs to Task 3,
        // and a row appearing here would mean issuance grew a second owner.
        $this->issuer()->issue(DB::connection('issuer_a'), $this->grant($this->user()));

        self::assertSame(0, DB::table('auth_token_assurances')->count());
    }
}
