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
use Fissible\Vouch\Tokens\CredentialLockManager;
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

        // Live host authentication, since issuance resolves the session from it.
        $this->actingAs(TokenUser::query()->findOrFail(7));
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
    public function it_acquires_the_subject_lock_before_any_credential_lock(): void
    {
        /*
         * ORDER IS THE DEADLOCK PROOF, and it is asserted through a seam rather
         * than by observing SQL.
         *
         * An earlier draft filtered "for update" statements out of DB::listen
         * and compared the captured bindings against those same bindings cast to
         * int — so every order passed, and the subject lock was never checked at
         * all. It proved the test's own filter. Worse, I told the reviewer I had
         * deleted it and had not; this is that deletion.
         *
         * A recording fake makes the sequence observable without reproducing a
         * deadlock, which is the failure that by definition does not reproduce
         * on demand. The contract: ONE acquire() call, subject first, then the
         * credential ids deduplicated and ascending.
         */
        $this->credentials();
        $this->establishedSessionFor();

        $recorder = $this->recordingLocks();

        Vouch::issueToken($this->grant());

        self::assertCount(1, $recorder->calls, 'Locks must be acquired once, not per credential.');
        self::assertSame($this->subject()->render(), $recorder->calls[0]['subject']);
        self::assertNotSame([], $recorder->calls[0]['credentials']);
    }

    #[Test]
    public function it_locks_every_credential_in_the_proof_deduplicated_and_ascending(): void
    {
        /*
         * EVERY credential in the proof, not the subset a policy branch needed —
         * an unlocked credential can be disabled between revalidation and
         * commit. Deduplicated, because two factors on one authenticator are one
         * credential. Ascending, because two operations holding the same
         * credentials must take them in one order or they can cross.
         *
         * The proof is deliberately ordered NEWEST first, so an implementation
         * locking in proof order takes them backwards and fails.
         */
        $password = AuthCredential::query()->where('user_id', 7)->where('type', 'password')->firstOrFail();
        app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example']);
        $totp = AuthCredential::query()->where('user_id', 7)->where('type', 'totp')->firstOrFail();

        $this->actingAs(TokenUser::query()->findOrFail(7));
        session()->start();

        $factors = [
            new SatisfiedFactor('totp', (string) $totp->id, FactorKind::Possession, FactorStrength::Possession,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:05:00+00:00')),
            new SatisfiedFactor('password', (string) $password->id, FactorKind::Knowledge, FactorStrength::Knowledge,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00')),
            // The same authenticator again: one credential, one lock.
            new SatisfiedFactor('totp_uv', (string) $totp->id, FactorKind::Possession, FactorStrength::PossessionStrong,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:06:00+00:00')),
        ];
        app(SessionLifecycle::class)->establish(
            new AuthSuccess(7, $factors, AssuranceFacts::fromFactors($factors), 'ignored', 'ignored'),
        );

        $recorder = $this->recordingLocks();

        Vouch::issueToken($this->grant());

        $expected = [(string) $password->id, (string) $totp->id];
        sort($expected);

        self::assertSame($expected, $recorder->calls[0]['credentials']);
    }

    /**
     * A lock manager that records instead of locking.
     *
     * Built as an anonymous class INSIDE a method on purpose. A file-scope
     * subclass of a not-yet-existing class is a fatal at load time, which
     * aborts the entire suite rather than failing the tests that need it — and
     * in a test-first phase that hides every other result.
     *
     * Deliberately a recorder rather than a mock: the assertion is about the
     * sequence the protocol requires, which belongs in the test body rather
     * than in expectation setup.
     */
    private function recordingLocks(): object
    {
        $recorder = new class extends CredentialLockManager {
            /** @var list<array{subject: string, credentials: list<string>}> */
            public array $calls = [];

            /** @param list<string> $credentialIds */
            public function acquire(SubjectKey $subject, array $credentialIds): void
            {
                $this->calls[] = ['subject' => $subject->render(), 'credentials' => $credentialIds];
            }
        };

        app()->instance(CredentialLockManager::class, $recorder);

        return $recorder;
    }
}
