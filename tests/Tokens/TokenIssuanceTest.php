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
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\RevokedReason;
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
use Laravel\Sanctum\PersonalAccessToken;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 3 — what it takes to mint a token.
 *
 * Issuance is the one place a long-lived credential is created from a
 * short-lived one, so every refusal here is a refusal to convert a session into
 * something that outlives it.
 *
 * THE SESSION IS RESOLVED, NOT SUPPLIED. An earlier draft took an AuthSession
 * parameter, which makes the caller's Eloquent object the authority: a stale
 * model still holds the proof and revoked_at it was loaded with, so a caller
 * could hand over a session the database has since killed. Live host
 * authentication is what establishes current validity, and the server row is
 * re-read under the lock.
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
        // same parser and evaluator as login. A separate mechanism would be a
        // second policy language to keep in step with the first.
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

    /**
     * Enrol REAL credentials and return them by factor id.
     *
     * Issuance revalidates and locks the credentials named in the proof, so a
     * proof carrying invented ids can only ever be refused. An earlier draft
     * used 'cred-1'/'cred-2' literals, which would have made every success test
     * unsatisfiable against a correct implementation.
     *
     * @return array<string, AuthCredential>
     */
    private function enrolled(int $userId = 7): array
    {
        app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll($userId, ['password' => 'correct horse battery staple']);
        app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->enroll($userId, ['label' => 'ada@acme.example']);

        return [
            'password' => AuthCredential::query()->where('user_id', $userId)->where('type', 'password')->firstOrFail(),
            'totp' => AuthCredential::query()->where('user_id', $userId)->where('type', 'totp')->firstOrFail(),
        ];
    }

    /** @param list<string> $factorIds */
    private function establishedSession(int $userId = 7, array $factorIds = ['password', 'totp']): AuthSession
    {
        $credentials = $this->enrolled($userId);
        $at = ['password' => '2026-08-13T10:00:00+00:00', 'totp' => '2026-08-13T10:05:00+00:00'];
        $strength = ['password' => FactorStrength::Knowledge, 'totp' => FactorStrength::Possession];

        // The KINDS the shipped drivers actually emit. An earlier draft marked
        // totp as Knowledge, which persists evidence no real login could
        // produce and would mask an implementation that copied the wrong field.
        $kind = ['password' => FactorKind::Knowledge, 'totp' => FactorKind::Possession];

        $factors = array_map(
            fn (string $id): SatisfiedFactor => new SatisfiedFactor(
                $id, (string) $credentials[$id]->id, $kind[$id], $strength[$id],
                false, false, false, null, new DateTimeImmutable($at[$id]),
            ),
            $factorIds,
        );

        // AUTHENTICATE THE HOST GUARD. Issuance resolves the session from live
        // host authentication, so a helper that only writes an auth_sessions row
        // would let every test here pass against an implementation that trusts a
        // surviving Vouch row after logout.
        $this->actingAs(TokenUser::query()->findOrFail($userId));
        session()->start();

        app(SessionLifecycle::class)->establish(
            new AuthSuccess($userId, $factors, AssuranceFacts::fromFactors($factors), 'ignored', 'ignored'),
        );

        return AuthSession::query()->where('user_id', $userId)->firstOrFail();
    }

    private function grant(int $subjectId = 7, ?string $tenantId = null): TokenGrant
    {
        return new TokenGrant($this->subject($subjectId), 'api', ['orders:read'], $tenantId);
    }

    #[Test]
    public function it_issues_from_a_session_whose_proof_satisfies_the_intent(): void
    {
        $this->establishedSession();

        $issued = Vouch::issueToken($this->grant());

        self::assertNotSame('', $issued->plainText);
        self::assertSame(1, DB::table('auth_token_assurances')->count());
        self::assertSame(2, DB::table('auth_token_credentials')->count());
    }

    #[Test]
    public function it_refuses_to_mint_for_a_subject_other_than_the_session_holder(): void
    {
        /*
         * THE substitution guard. A caller that can name the subject could
         * otherwise mint a token for anyone from their own session — the whole
         * of authentication bypassed by one parameter. The resolved session is
         * the authority; the grant's subject is a request.
         */
        $this->establishedSession(userId: 7);

        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($this->grant(subjectId: 8));
    }

    #[Test]
    public function it_refuses_when_no_session_is_authenticated(): void
    {
        // No host session at all. Issuance has no authority to draw on and must
        // not fall back to an ambient user.
        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($this->grant());
    }

    #[Test]
    public function it_refuses_a_revoked_session(): void
    {
        // A token minted from a revoked session is a revocation that did not
        // take: the session is dead and its holder walks away with a credential
        // that outlives it.
        $session = $this->establishedSession();
        $session->update(['revoked_at' => now(), 'revoked_reason' => RevokedReason::Logout]);

        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($this->grant());
    }

    #[Test]
    public function it_refuses_a_session_revoked_after_the_request_began(): void
    {
        /*
         * THE staleness guard, and the reason the session is re-read rather than
         * trusted. An in-memory model still carries the revoked_at it was loaded
         * with, so an implementation holding one from earlier in the request
         * issues happily against a session the database has since killed.
         */
        $session = $this->establishedSession();

        // Revoked by another request, invisible to anything already loaded.
        DB::table('auth_sessions')->where('id', $session->id)
            ->update(['revoked_at' => now(), 'revoked_reason' => RevokedReason::Logout->value]);

        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($this->grant());
    }

    #[Test]
    public function it_refuses_a_recovery_grace_session(): void
    {
        // Grace is a restricted recovery capability. Minting from it converts a
        // recovery flow into a durable credential, which is more than recovery
        // was ever allowed to grant.
        $session = $this->establishedSession();
        DB::table('auth_sessions')->where('id', $session->id)
            ->update(['recovery_grace_expires_at' => now()->addMinutes(15)]);

        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($this->grant());
    }

    #[Test]
    public function it_refuses_a_session_whose_proof_does_not_satisfy_the_intent(): void
    {
        // token_issue requires password AND totp; this session proved only a
        // password, so it may browse but may not mint.
        $this->establishedSession(factorIds: ['password']);

        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($this->grant());
    }

    #[Test]
    public function it_selects_a_satisfying_branch_through_the_ordinary_evaluator(): void
    {
        /*
         * PROVES REUSE, not just outcome. A stub hard-coding "password and totp"
         * satisfies every other policy test here. This one uses a policy whose
         * correct answer requires real parsing and real branch selection:
         *
         *     any_of: [ all_of:[totp], all_of:[password, totp] ]
         *
         * The session proved BOTH factors, so it satisfies the policy either
         * way — but the recorded mappings must still carry EVERY credential the
         * session actually used, per addendum §3 as amended. An implementation
         * that recorded the winning branch would map totp alone, and disabling
         * the password would then fail to revoke a token it helped authorize.
         */
        AuthPolicy::query()->where('scope', 'token_issue')->update([
            'document' => ['any_of' => [['all_of' => ['totp']], ['all_of' => ['password', 'totp']]]],
        ]);

        $credentials = $this->enrolledFromSession($this->establishedSession());

        Vouch::issueToken($this->grant());

        $mapped = DB::table('auth_token_credentials')->orderBy('credential_id')->pluck('credential_id')->all();

        self::assertSame(
            $credentials,
            array_map(static fn (mixed $c): string => stringValue($c), $mapped),
            'The mapping recorded a policy branch rather than the session proof.',
        );
    }

    /** @return list<string> credential ids in the session proof, ascending */
    private function enrolledFromSession(AuthSession $session): array
    {
        $proof = \Fissible\Vouch\Sessions\SessionEvidence::for($session);
        self::assertNotNull($proof);

        $ids = array_map(static fn (SatisfiedFactor $f): string => $f->credentialId, $proof->factors);
        sort($ids);

        return $ids;
    }

    #[Test]
    public function it_refuses_a_session_carrying_no_proof(): void
    {
        // A pre-2.4 session cannot mint: it has no evidence to evaluate, and
        // adopting its cached acr would assert a fact nobody witnessed.
        session()->start();
        AuthSession::query()->create([
            'session_binding' => \Fissible\Vouch\Sessions\SessionBinding::for(session()->getId(), \Fissible\Vouch\Sessions\BindingDomain::Session),
            'user_id' => 7,
            'amr' => ['password', 'totp'],
            'acr' => 'aal2',
            'assurance_proof' => null,
        ]);

        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($this->grant());
    }

    #[Test]
    public function it_records_the_proof_the_session_actually_held(): void
    {
        /*
         * The token inherits the SESSION's evidence, not a fresh assertion. If
         * issuance recorded anything else, a token could outrank the login that
         * produced it.
         */
        $this->establishedSession();

        Vouch::issueToken($this->grant());

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
    public function it_never_persists_the_plaintext(): void
    {
        /*
         * The plaintext is returned once and stored nowhere. Sanctum hashes its
         * own column — included here because it is the likeliest place for a
         * plaintext to survive by accident, and the one Vouch does not own.
         */
        $this->establishedSession();

        $plain = Vouch::issueToken($this->grant())->plainText;

        foreach (['auth_token_assurances', 'auth_token_credentials', 'auth_sessions', 'personal_access_tokens'] as $table) {
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
    public function an_ordinary_logout_does_not_revoke_the_tokens_a_session_minted(): void
    {
        /*
         * A token is a durable credential in its own right. Ordinary logout and
         * administrative session revocation must NOT cascade, or every API token
         * dies whenever its creator closes a browser tab.
         *
         * Deliberately labelled Logout rather than PasswordChanged: credential
         * change has its own subject-wide sweep (§6.5), and that cascade is
         * Task 5's to prove. Using a credential-change reason here would assert
         * the opposite of what Task 5 must establish.
         */
        $this->establishedSession();
        $issued = Vouch::issueToken($this->grant());

        DB::table('auth_sessions')->update(['revoked_at' => now(), 'revoked_reason' => RevokedReason::Logout->value]);

        self::assertSame(1, PersonalAccessToken::query()->count());
        self::assertSame(
            1,
            DB::table('auth_token_assurances')->where('token_key', $issued->tokenKey)->count(),
            'Session revocation destroyed a token assurance record it does not own.',
        );
    }

    #[Test]
    public function client_abilities_never_become_policy_input(): void
    {
        /*
         * The grant's abilities cross the boundary uninterpreted. If a wider
         * ability list could ease issuance, a client would be choosing its own
         * assurance requirement by asking for more.
         */
        $this->establishedSession();

        Vouch::issueToken(new TokenGrant($this->subject(), 'wide', ['*', 'admin:everything']));

        self::assertSame('aal2', DB::table('auth_token_assurances')->value('acr'));
    }

    #[Test]
    public function tenant_scoped_issuance_is_unreachable_until_sessions_carry_a_tenant(): void
    {
        /*
         * RECORDED LIMITATION, not a passing feature. SessionLifecycle writes
         * evidence with a null tenant, so no session can currently produce
         * tenant-scoped evidence, and a tenant grant has nothing to match
         * against. Issuance must refuse rather than mint a token under a policy
         * that never governed the login.
         *
         * The same shape as aal3 being unsatisfiable with the shipped
         * vocabulary: the refusal is correct today, and the capability arrives
         * only when session evidence learns to carry a tenant. Task 3 does not
         * add that; asserting the refusal stops the gap being mistaken for
         * support.
         */
        $this->establishedSession();

        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($this->grant(tenantId: 'acme'));
    }

    #[Test]
    public function it_refuses_when_the_vouch_row_outlives_the_host_login(): void
    {
        /*
         * THE discriminating case for resolving from live authentication. The
         * auth_sessions row is intact and not revoked — only the host principal
         * is gone, which is what an ordinary logout leaves behind until the
         * record is pruned.
         *
         * An implementation that looks the row up by binding and asks no further
         * question mints happily here, and every other test in this file passes
         * for it.
         */
        $this->establishedSession();

        auth()->logout();

        $this->expectException(IssuanceRefused::class);

        Vouch::issueToken($this->grant());
    }
}