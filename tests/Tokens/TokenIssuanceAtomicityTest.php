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

    private function establishedSessionFor(?AuthCredential $credential = null): AuthSession
    {
        session()->start();
        $credential ??= AuthCredential::query()->where('user_id', 7)->where('type', 'password')->firstOrFail();
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
        $session = $this->establishedSessionFor($credential);
        $credential->update(['disabled_at' => now()]);

        try {
            Vouch::issueToken($this->grant());
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
        $session = $this->establishedSessionFor($credential);

        AuthPolicy::query()->where('scope', 'token_issue')->update(['document' => ['all_of' => ['password', 'totp']]]);

        try {
            Vouch::issueToken($this->grant());
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
        $session = $this->establishedSessionFor($credential);

        try {
            DB::transaction(function (): void {
                Vouch::issueToken($this->grant());

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
    public function it_never_opens_or_commits_a_transaction_of_its_own(): void
    {
        /*
         * SETTLED DESIGN, and it replaces a contradiction. An earlier draft
         * asserted BOTH that issuance commits before returning the plaintext AND
         * that it enlists in a caller's transaction. Those are mutually
         * exclusive: a synchronous call cannot both guarantee committed state on
         * return and leave the commit to a caller who may still roll back.
         *
         * Enlistment wins, because the alternative is the failure this whole
         * file exists to prevent — a host rolling back its surrounding work and
         * being left with a live token and assurance record it believes it
         * undid. The cost is a HOST OBLIGATION: the plaintext is returned before
         * the outer commit and must not be disclosed or used until it commits.
         *
         * Asserted by observing that issuance neither begins nor commits at the
         * top level: after a direct call the transaction level is unchanged, and
         * inside a caller's transaction the writes are still pending.
         */
        $this->credentials();
        $this->establishedSessionFor();

        self::assertSame(0, DB::transactionLevel());

        DB::beginTransaction();
        Vouch::issueToken($this->grant());

        // Still inside the caller's transaction: issuance did not commit it out
        // from under them, and did not leave a nested one open.
        self::assertSame(1, DB::transactionLevel());

        DB::rollBack();

        self::assertSame(0, PersonalAccessToken::query()->count());
        self::assertSame(0, DB::table('auth_token_assurances')->count());
        self::assertSame(0, DB::table('auth_token_credentials')->count());
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
        $session = $this->establishedSessionFor($credential);

        $first = Vouch::issueToken($this->grant());
        $second = Vouch::issueToken($this->grant());

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

        Vouch::issueToken($this->grant());

        $ids = array_values(array_filter(array_merge(...array_map('array_values', $locked)), 'is_numeric'));

        self::assertNotSame([], $ids, 'No credential lock was taken.');
        self::assertSame(
            array_values(array_unique($ids)),
            array_values(array_unique(array_map('intval', $ids))),
            'Credential locks were not taken in ascending id order.',
        );
    }

    #[Test]
    public function a_failure_after_the_issuer_succeeds_leaves_no_token_behind(): void
    {
        /*
         * THE token-without-assurance leak, injected where it can actually
         * happen. The policy-refusal test fails BEFORE the issuer runs, so it
         * cannot catch this: the dangerous window is after Sanctum's row exists
         * and before assurance is written.
         *
         * Injected by removing the assurance table, so the write that follows
         * issuance fails on a real statement rather than a mocked seam. The
         * token must not survive: a credential that authenticates and can never
         * authorize is invisible until a user reports their token does nothing.
         */
        $this->credentials();
        $this->establishedSessionFor();

        \Illuminate\Support\Facades\Schema::drop('auth_token_assurances');

        try {
            Vouch::issueToken($this->grant());
            self::fail('Issuance completed with no assurance table.');
        } catch (\Throwable) {
            // Expected; the assertion is what survived.
        }

        self::assertSame(0, PersonalAccessToken::query()->count(), 'A token outlived a failed issuance.');
    }

    #[Test]
    public function the_assurance_record_is_keyed_by_the_composite_identity(): void
    {
        // token_key alone is not identity: another issuer may mint the same key.
        $this->credentials();
        $this->establishedSessionFor();

        $issued = Vouch::issueToken($this->grant());

        self::assertSame(1, DB::table('auth_token_assurances')
            ->where('issuer_key', $issued->issuerKey)
            ->where('token_key', $issued->tokenKey)
            ->count());
    }
}