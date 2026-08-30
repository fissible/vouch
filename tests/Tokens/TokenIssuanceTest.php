<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use DateTimeImmutable;
use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\IssuanceRefused;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenGrant;
use Fissible\Vouch\Vouch;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 3 — what it takes to mint a token.
 *
 * Issuance is the one place a long-lived credential is created from a
 * short-lived one, so every refusal here is a refusal to convert a session into
 * something that outlives it. The session requirements are not ceremony: a
 * token minted from a revoked session is a revocation that did not take, and a
 * token minted from a grace session is a recovery flow that granted more than
 * recovery.
 */
final class TokenIssuanceTest extends TestCase
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
        TokenUser::query()->create(['id' => 8, 'name' => 'grace']);

        // token_issue is an ordinary Vouch policy scope, resolved through the
        // same parser and evaluator as login. A separate mechanism here would
        // be a second policy language to keep in step with the first.
        AuthPolicy::query()->create([
            'tenant_id' => null,
            'scope' => 'token_issue',
            'document' => ['all_of' => ['password', 'totp']],
            'posture' => 'friendly',
        ]);
    }

    private function subject(int $id = 7): SubjectKey
    {
        return SubjectKey::of((new TokenUser)->getMorphClass(), $id);
    }

    /** @return list<SatisfiedFactor> */
    private function proof(): array
    {
        return [
            new SatisfiedFactor('password', 'cred-1', FactorKind::Knowledge, FactorStrength::Knowledge,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00')),
            new SatisfiedFactor('totp', 'cred-2', FactorKind::Possession, FactorStrength::Possession,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:05:00+00:00')),
        ];
    }

    /** @param list<SatisfiedFactor>|null $factors */
    private function establishedSession(int $userId = 7, ?array $factors = null): AuthSession
    {
        session()->start();
        $factors ??= $this->proof();

        app(SessionLifecycle::class)->establish(
            new AuthSuccess($userId, $factors, AssuranceFacts::fromFactors($factors), 'ignored', 'ignored'),
        );

        return AuthSession::query()->where('user_id', $userId)->firstOrFail();
    }

    private function grant(int $subjectId = 7, ?string $tenantId = null, ActorKind $actor = ActorKind::Human): TokenGrant
    {
        return new TokenGrant($this->subject($subjectId), 'api', ['orders:read'], $tenantId, $actor);
    }

    #[Test]
    public function it_issues_from_a_session_whose_proof_satisfies_the_intent(): void
    {
        $issued = Vouch::issueToken($this->establishedSession(), $this->grant());

        self::assertNotSame('', $issued->plainTextToken);
        self::assertSame(1, DB::table('auth_token_assurances')->count());
        self::assertSame(2, DB::table('auth_token_credentials')->count());
    }

    #[Test]
    public function it_refuses_to_mint_for_a_subject_other_than_the_session_holder(): void
    {
        /*
         * THE substitution guard. A caller that can name the subject can
         * otherwise mint a token for anyone from their own session — the whole
         * of authentication bypassed by one parameter. The session's subject is
         * the authority; the grant's subject is a request.
         */
        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($this->establishedSession(userId: 7), $this->grant(subjectId: 8));
    }

    #[Test]
    public function it_refuses_a_revoked_session(): void
    {
        // A token minted from a revoked session is a revocation that did not
        // take: the session is dead and its holder walks away with a credential
        // that outlives it.
        $session = $this->establishedSession();
        $session->update(['revoked_at' => now(), 'revoked_reason' => RevokedReason::PasswordChanged]);

        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($session->fresh(), $this->grant());
    }

    #[Test]
    public function it_refuses_a_recovery_grace_session(): void
    {
        // Grace is a restricted recovery capability. Minting from it converts a
        // recovery flow into a durable credential, which is more than recovery
        // was ever allowed to grant.
        $session = $this->establishedSession();
        $session->update(['recovery_grace_expires_at' => now()->addMinutes(15)]);

        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($session->fresh(), $this->grant());
    }

    #[Test]
    public function it_refuses_a_session_whose_proof_does_not_satisfy_the_intent(): void
    {
        /*
         * The policy refusal. token_issue here requires password AND totp; this
         * session proved only a password, so it may browse but may not mint.
         */
        $weak = [new SatisfiedFactor('password', 'cred-1', FactorKind::Knowledge, FactorStrength::Knowledge,
            false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'))];

        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($this->establishedSession(factors: $weak), $this->grant());
    }

    #[Test]
    public function it_refuses_a_session_carrying_no_proof(): void
    {
        // A pre-2.4 session cannot mint. It has no evidence to evaluate, and
        // adopting its cached acr would assert a fact nobody witnessed.
        $legacy = AuthSession::query()->create([
            'session_binding' => str_repeat('z', 64),
            'user_id' => 7,
            'amr' => ['password', 'totp'],
            'acr' => 'aal2',
            'assurance_proof' => null,
        ]);

        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($legacy, $this->grant());
    }

    #[Test]
    public function it_records_the_proof_the_session_actually_held(): void
    {
        /*
         * The token inherits the SESSION's evidence, not a fresh assertion. If
         * issuance recorded anything else, a token could outrank the login that
         * produced it — and the whole point of deriving assurance from evidence
         * would be lost at the one boundary that creates durable credentials.
         */
        Vouch::issueToken($this->establishedSession(), $this->grant());

        $row = DB::table('auth_token_assurances')->first();

        self::assertNotNull($row);
        self::assertSame('aal2', $row->acr);
        self::assertSame($this->subject()->render(), $row->subject_key);
        self::assertSame('human', $row->actor_kind);
        self::assertSame(
            '2026-08-13 10:00:00',
            substr(stringValue($row->weakest_satisfied_at), 0, 19),
            'The anchor must be the session proof oldest factor, never the issuance moment.',
        );
    }

    #[Test]
    public function it_maps_every_credential_in_the_proof(): void
    {
        Vouch::issueToken($this->establishedSession(), $this->grant());

        $mapped = DB::table('auth_token_credentials')->orderBy('credential_id')->pluck('credential_id')->all();

        self::assertSame(['cred-1', 'cred-2'], array_map(static fn (mixed $c): string => stringValue($c), $mapped));
    }

    #[Test]
    public function it_never_persists_the_plaintext(): void
    {
        /*
         * The plaintext is returned once and stored nowhere. Sanctum hashes its
         * own column; the risk is Vouch's tables, which are new and adjacent and
         * would be the last place anyone thought to look.
         */
        $issued = Vouch::issueToken($this->establishedSession(), $this->grant());
        $plain = $issued->plainTextToken;

        foreach (['auth_token_assurances', 'auth_token_credentials', 'auth_sessions'] as $table) {
            foreach (DB::table($table)->get() as $row) {
                self::assertStringNotContainsString(
                    $plain,
                    stringValue(json_encode($row)),
                    "The plaintext token leaked into {$table}.",
                );
            }
        }
    }

    #[Test]
    public function the_issued_token_authorizes_without_consulting_the_session(): void
    {
        /*
         * THE GATE for this task. A token is a durable credential in its own
         * right: once issued it must stand on its recorded evidence, so
         * revoking the session that minted it does not silently revoke every
         * token derived from it.
         *
         * That is a deliberate policy rather than an oversight — §6.5 gives
         * credential change its own sweep precisely because session revocation
         * is NOT it.
         */
        $session = $this->establishedSession();
        $issued = Vouch::issueToken($session, $this->grant());

        $session->update(['revoked_at' => now(), 'revoked_reason' => RevokedReason::PasswordChanged]);

        $record = app(\Fissible\Vouch\Tokens\TokenAssuranceRecord::class)->read(
            new \Fissible\Vouch\Tokens\ResolvedToken('sanctum', $issued->tokenKey, $this->subject(), true),
        );

        self::assertNotNull($record->evidence);
        self::assertSame('aal2', $record->evidence->derivedAcr());
    }

    #[Test]
    public function client_abilities_never_become_policy_input(): void
    {
        /*
         * The grant's abilities cross the boundary uninterpreted. If a wider
         * ability list could ease issuance, a client would be choosing its own
         * assurance requirement by asking for more.
         */
        $narrow = Vouch::issueToken($this->establishedSession(), new TokenGrant($this->subject(), 'a', ['orders:read']));

        DB::table('auth_token_assurances')->delete();
        DB::table('auth_token_credentials')->delete();

        $wide = Vouch::issueToken($this->establishedSession(), new TokenGrant($this->subject(), 'b', ['*', 'admin:everything']));

        self::assertSame(
            DB::table('auth_token_assurances')->value('acr'),
            'aal2',
            'A wider ability list changed the recorded assurance.',
        );
        self::assertNotSame($narrow->plainTextToken, $wide->plainTextToken);
    }

    #[Test]
    public function a_tenant_scoped_session_mints_a_tenant_scoped_token(): void
    {
        // Tenancy travels with the evidence. A global session minting a
        // tenant-scoped token would create evidence under a policy that never
        // governed it.
        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($this->establishedSession(), $this->grant(tenantId: 'acme'));
    }
}
