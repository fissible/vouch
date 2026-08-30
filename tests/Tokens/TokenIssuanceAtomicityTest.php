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
 * 2.4 Task 3 — issuance is one transaction, or it is a leak.
 *
 * Issuance writes in three places: the issuer's own table, the assurance record,
 * and the credential mappings. Every partial combination is a distinct failure
 * with its own blast radius, and none of them announce themselves:
 *
 *  - token without assurance   -> default-deny refuses it forever; the holder
 *                                 has a credential that never works.
 *  - assurance without token   -> a record no revocation sweep can reach,
 *                                 because the token it names does not exist.
 *  - assurance without mappings-> disabling the credential fails to revoke the
 *                                 token that credential authorized.
 *
 * The gate for this task is that a failed issuance leaves NONE of them.
 */
final class TokenIssuanceAtomicityTest extends TestCase
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
            'document' => ['all_of' => ['password']],
            'posture' => 'friendly',
        ]);
    }

    private function subject(): SubjectKey
    {
        return SubjectKey::of((new TokenUser)->getMorphClass(), 7);
    }

    /** Enrol real credentials so issuance has something to revalidate and lock. */
    private function credentials(): AuthCredential
    {
        app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);

        return AuthCredential::query()->where('user_id', 7)->where('type', 'password')->firstOrFail();
    }

    private function establishedSession(AuthCredential $credential): AuthSession
    {
        session()->start();
        $factors = [new SatisfiedFactor('password', (string) $credential->id, FactorKind::Knowledge,
            FactorStrength::Knowledge, false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'))];

        app(SessionLifecycle::class)->establish(
            new AuthSuccess(7, $factors, AssuranceFacts::fromFactors($factors), 'ignored', 'ignored'),
        );

        return AuthSession::query()->firstOrFail();
    }

    private function grant(): TokenGrant
    {
        return new TokenGrant($this->subject(), 'api', ['orders:read']);
    }

    #[Test]
    public function it_refuses_when_a_credential_in_the_proof_is_no_longer_valid(): void
    {
        /*
         * Revalidation under the lock, and the race it closes: the session's
         * proof was true when the login happened, and issuance is a LATER
         * moment. A credential disabled in between must stop the token being
         * minted, or a disable races an issuance and loses silently.
         */
        $credential = $this->credentials();
        $session = $this->establishedSession($credential);
        $credential->update(['disabled_at' => now()]);

        try {
            Vouch::issueToken($session, $this->grant());
            self::fail('Issuance proceeded on a disabled credential.');
        } catch (IssuanceRefused) {
            // Expected.
        }

        self::assertSame(0, PersonalAccessToken::query()->count());
        self::assertSame(0, DB::table('auth_token_assurances')->count());
        self::assertSame(0, DB::table('auth_token_credentials')->count());
    }

    #[Test]
    public function a_refusal_leaves_no_token_behind(): void
    {
        /*
         * The ordering that makes this hard: the issuer creates the token
         * BEFORE assurance is written, so a later refusal must undo a side
         * effect in someone else's table. A token surviving here is a
         * credential that authenticates and can never authorize — invisible
         * until a user reports that their token does nothing.
         */
        $credential = $this->credentials();
        $session = $this->establishedSession($credential);

        AuthPolicy::query()->where('scope', 'token_issue')->update(['document' => ['all_of' => ['password', 'totp']]]);

        try {
            Vouch::issueToken($session, $this->grant());
            self::fail('Issuance proceeded against an unsatisfied policy.');
        } catch (IssuanceRefused) {
            // Expected.
        }

        self::assertSame(0, PersonalAccessToken::query()->count());
        self::assertSame(0, DB::table('auth_token_assurances')->count());
    }

    #[Test]
    public function a_caller_rollback_undoes_the_token_as_well_as_the_assurance(): void
    {
        /*
         * Issuance must enlist in an enclosing transaction rather than commit
         * its own. A host that wraps issuance with its own writes and rolls back
         * must not be left with a live token, and Sanctum's row is the one most
         * likely to escape because it is written through a different model on a
         * connection Vouch was handed rather than one it opened.
         */
        $credential = $this->credentials();
        $session = $this->establishedSession($credential);

        try {
            DB::transaction(function () use ($session): void {
                Vouch::issueToken($session, $this->grant());

                throw new \RuntimeException('The host failed after issuance.');
            });
        } catch (\RuntimeException) {
            // Expected.
        }

        self::assertSame(0, PersonalAccessToken::query()->count());
        self::assertSame(0, DB::table('auth_token_assurances')->count());
        self::assertSame(0, DB::table('auth_token_credentials')->count());
    }

    #[Test]
    public function it_commits_before_returning_the_plaintext(): void
    {
        /*
         * The plaintext is the only copy that ever exists. Returning it before
         * the commit means a caller can hold a working-looking token for a
         * transaction that then rolls back — and unlike every other failure
         * here, the user has already been shown the value.
         */
        $credential = $this->credentials();
        $issued = Vouch::issueToken($this->establishedSession($credential), $this->grant());

        // Read on a fresh connection so an uncommitted write cannot answer.
        DB::disconnect();

        self::assertSame(1, DB::table('auth_token_assurances')->count());
        self::assertSame(1, PersonalAccessToken::query()->count());
        self::assertNotSame('', $issued->plainTextToken);
    }

    #[Test]
    public function one_canonical_identity_yields_one_assurance_row(): void
    {
        /*
         * Two rows for one token would let a reader pick whichever assurance
         * suited it. Issuing twice must produce two DISTINCT tokens, each with
         * exactly one record — not one token with two.
         */
        $credential = $this->credentials();
        $session = $this->establishedSession($credential);

        $first = Vouch::issueToken($session, $this->grant());
        $second = Vouch::issueToken($session, $this->grant());

        self::assertNotSame($first->tokenKey, $second->tokenKey);
        self::assertSame(2, DB::table('auth_token_assurances')->count());

        foreach ([$first->tokenKey, $second->tokenKey] as $key) {
            self::assertSame(1, DB::table('auth_token_assurances')->where('token_key', $key)->count());
        }
    }

    #[Test]
    public function it_locks_every_credential_in_the_proof_in_id_order(): void
    {
        /*
         * Deterministic order is what makes issuance and revocation unable to
         * deadlock: two operations holding the same credentials must take them
         * in one order. Asserted by observing the statements rather than the
         * outcome, because a deadlock is precisely the failure that does not
         * reproduce on demand.
         *
         * Ordered by credential id, and EVERY credential in the proof — not the
         * subset a policy branch needed, since an unlocked credential can be
         * disabled between revalidation and commit.
         */
        app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
        app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example']);

        $password = AuthCredential::query()->where('user_id', 7)->where('type', 'password')->firstOrFail();
        $totp = AuthCredential::query()->where('user_id', 7)->where('type', 'totp')->firstOrFail();

        session()->start();

        // Deliberately proof-ordered NEWEST first, so an implementation that
        // locks in proof order rather than id order takes them backwards.
        $factors = [
            new SatisfiedFactor('totp', (string) $totp->id, FactorKind::Possession, FactorStrength::Possession,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:05:00+00:00')),
            new SatisfiedFactor('password', (string) $password->id, FactorKind::Knowledge, FactorStrength::Knowledge,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00')),
        ];
        app(SessionLifecycle::class)->establish(
            new AuthSuccess(7, $factors, AssuranceFacts::fromFactors($factors), 'ignored', 'ignored'),
        );

        $locked = [];
        DB::listen(function ($query) use (&$locked): void {
            if (str_contains($query->sql, 'auth_credentials') && str_contains(strtolower($query->sql), 'for update')) {
                $locked[] = $query->bindings;
            }
        });

        Vouch::issueToken(AuthSession::query()->firstOrFail(), $this->grant());

        $ids = array_values(array_filter(array_merge(...array_map('array_values', $locked)), 'is_numeric'));

        self::assertNotSame([], $ids, 'No credential lock was taken.');
        self::assertSame(
            array_values(array_unique($ids)),
            array_values(array_unique(array_map('intval', $ids))),
            'Credential locks were not taken in ascending id order.',
        );
    }
}
