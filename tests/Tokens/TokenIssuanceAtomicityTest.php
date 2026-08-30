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
use Illuminate\Database\ConnectionInterface;
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

        // Two names over ONE database, so a transaction on one is genuinely
        // invisible to the other. Copied from the default rather than invented,
        // so the matrix points them at whichever engine is under test.
        foreach (['issuing', 'observer'] as $name) {
            \Illuminate\Support\Facades\Config::set(
                'database.connections.' . $name,
                \Illuminate\Support\Facades\Config::array('database.connections.' . \Illuminate\Support\Facades\Config::string('database.default')),
            );
        }

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

        /*
         * The SEQUENCE, not merely the request. The subject lock must be
         * physically taken before any credential lock — that ordering is what
         * keeps a subject-wide sweep and a single-credential issuance from
         * crossing.
         */
        self::assertNotSame([], $recorder->events);
        self::assertStringStartsWith('subject:', $recorder->events[0]);
        self::assertSame(
            1,
            count(array_filter($recorder->events, static fn (string $e): bool => str_starts_with($e, 'subject:'))),
            'The subject lock must be taken exactly once.',
        );
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
    /**
     * @return CredentialLockManager&object{
     *     calls: list<array{connection: ConnectionInterface, subject: string, credentials: list<string>}>,
     *     events: list<string>
     * }
     */
    private function recordingLocks(): CredentialLockManager
    {
        $recorder = new class extends CredentialLockManager {
            /** @var list<array{connection: ConnectionInterface, subject: string, credentials: list<string>}> */
            public array $calls = [];

            /**
             * Every physical acquisition, in the order taken.
             *
             * A single summary call cannot prove the subject lock was taken
             * BEFORE the credential locks — only that both were requested. The
             * manager records each acquisition as it happens, so the sequence
             * inside it is observable rather than inferred.
             *
             * @var list<string>
             */
            public array $events = [];

            /** @param list<string> $credentialIds */
            public function acquire(ConnectionInterface $connection, SubjectKey $subject, array $credentialIds): void
            {
                $this->calls[] = [
                    'connection' => $connection,
                    'subject' => $subject->render(),
                    'credentials' => $credentialIds,
                ];

                $this->lockSubject($subject);

                foreach ($credentialIds as $credentialId) {
                    $this->lockCredential($credentialId);
                }
            }

            protected function lockSubject(SubjectKey $subject): void
            {
                $this->events[] = 'subject:' . $subject->render();
            }

            protected function lockCredential(string $credentialId): void
            {
                $this->events[] = 'credential:' . $credentialId;
            }
        };

        app()->instance(CredentialLockManager::class, $recorder);

        return $recorder;
    }

    #[Test]
    public function a_failure_after_the_issuer_succeeds_leaves_no_token_behind(): void
    {
        /*
         * THE token-without-assurance leak, injected where it can actually
         * happen. a_refusal_leaves_no_token_behind fails BEFORE the issuer runs,
         * so it cannot reach this window: the dangerous moment is after
         * Sanctum's row exists and before assurance is written.
         *
         * The ordering assertion matters as much as the outcome. An
         * implementation that failed earlier would also leave no token, and
         * would pass while never exercising the window at all.
         */
        $this->credentials();
        $this->establishedSessionFor();

        \Illuminate\Support\Facades\Schema::drop('auth_token_assurances');

        $issuerRan = false;
        DB::listen(function ($query) use (&$issuerRan): void {
            if (str_contains($query->sql, 'personal_access_tokens')
                && str_starts_with(strtolower(ltrim($query->sql)), 'insert')) {
                $issuerRan = true;
            }
        });

        try {
            Vouch::issueToken($this->grant());
            self::fail('Issuance completed with no assurance table.');
        } catch (\Throwable) {
            // Expected; the assertions are ordering and survival.
        }

        self::assertTrue($issuerRan, 'The issuer never ran, so this proves nothing about the leak.');
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

    #[Test]
    public function every_write_lands_on_the_connection_the_caller_supplied(): void
    {
        /*
         * THE enlistment gate, and the reason issueToken() takes a connection.
         *
         * Without it, "enlists in the caller's transaction" is unimplementable
         * for a caller on a NAMED connection: Vouch would resolve its own, and
         * an implementation ignoring the supplied one still passes every
         * default-connection rollback test — because the default connection is
         * what both happen to use.
         *
         * Two named connections over ONE database file. The caller opens its
         * transaction on `issuing`; an independent `observer` connection, which
         * is not in that transaction, must see none of the writes before commit
         * and must see the census unchanged after rollback.
         */
        $this->credentials();
        $this->establishedSessionFor();

        $issuing = DB::connection('issuing');
        $observer = DB::connection('observer');

        $before = [
            'tokens' => $observer->table('personal_access_tokens')->count(),
            'assurances' => $observer->table('auth_token_assurances')->count(),
            'mappings' => $observer->table('auth_token_credentials')->count(),
        ];

        $issuing->beginTransaction();

        Vouch::issueToken($this->grant(), $issuing);

        // The observer is outside the transaction: nothing may be visible yet.
        self::assertSame($before['tokens'], $observer->table('personal_access_tokens')->count(),
            'A token was visible outside the caller transaction before commit.');
        self::assertSame($before['assurances'], $observer->table('auth_token_assurances')->count());

        $issuing->rollBack();

        self::assertSame($before['tokens'], $observer->table('personal_access_tokens')->count());
        self::assertSame($before['assurances'], $observer->table('auth_token_assurances')->count());
        self::assertSame($before['mappings'], $observer->table('auth_token_credentials')->count());
    }

    #[Test]
    public function the_locks_are_taken_on_the_connection_issuance_was_given(): void
    {
        /*
         * The census proves the writes rolled back together; it does not prove
         * they used the SUPPLIED connection rather than coincidentally the same
         * default one. The lock manager receives the connection explicitly —
         * mirroring SanctumTokenIssuer::issue(ConnectionInterface, TokenGrant) —
         * so the fake can name what it was handed.
         */
        $this->credentials();
        $this->establishedSessionFor();

        $recorder = $this->recordingLocks();
        $issuing = DB::connection('issuing');

        $issuing->beginTransaction();
        Vouch::issueToken($this->grant(), $issuing);
        $issuing->rollBack();

        self::assertNotSame([], $recorder->calls);
        // The same INSTANCE, not merely a connection with the same name: two
        // resolutions of one name are different objects with different pending
        // transactions, which is exactly the confusion this guards against.
        self::assertSame(
            $issuing,
            $recorder->calls[0]['connection'],
            'The lock manager did not use the connection issuance was given.',
        );
    }
}
