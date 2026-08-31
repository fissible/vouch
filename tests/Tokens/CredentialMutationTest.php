<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use DateTimeImmutable;
use Fissible\Vouch\Credentials\CredentialMutation;
use Fissible\Vouch\Credentials\CredentialMutationResult;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Tokens\TokenIssuerRegistry;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;

/**
 * 2.4 Task 5b — the credential mutation protocol.
 *
 * The classification is the contract, and it exists because the obvious rule is
 * dangerous. `DatabaseAttemptStore::apply()` handles BOTH `DisableCredential`
 * and `AdvanceCredentialTimestep` — and the latter advances `last_used_timestep`
 * on every successful TOTP verification, because it is the replay guard. A
 * facade that routed "every credential write" through one revoking path would
 * make every TOTP login revoke the user's own tokens.
 *
 * So a caller does not merely pass through the facade; it must SAY which kind
 * of mutation it is performing. Three named entry points rather than one
 * general one, so the dangerous case cannot be reached by forgetting a flag:
 *
 *   additive()    — enroll or add. Preserves every existing token.
 *   revoking()    — disable, remove, replace. Revokes precisely the tokens
 *                   whose persisted proof cites the affected credentials.
 *   subjectWide() — password change. Sweeps this subject's HUMAN tokens.
 */
final class CredentialMutationTest extends TestCase
{
    use DatabaseMigrations;

    /** @return array<int, class-string> */
    protected function getPackageProviders($app): array
    {
        return [VouchServiceProvider::class];
    }

    private function subject(): SubjectKey
    {
        return SubjectKey::of(configuredUserProvider(), '7');
    }

    /*
     * Credential ids are NUMERIC strings here, deliberately.
     *
     * The package treats them as opaque strings for ORDERING -- '09' and '9'
     * are different credentials and primary-key order cannot express that --
     * but auth_credentials.id is a bigint, so a non-numeric id cannot exist and
     * locking one fails outright on PostgreSQL:
     *
     *   SQLSTATE[22P02] invalid input syntax for type bigint: "cred-1"
     *
     * Measured against a real PostgreSQL 16 rather than discovered in CI.
     *
     * My first reading of this was wrong and is corrected here: I took it to
     * mean the opacity applies to ORDER rather than to the alphabet. It does
     * not hold at all against this schema — with a bigint primary key, '09' and
     * '9' are the SAME row, so canonicalCredentialIds() gives a deterministic
     * ORDER over decimal strings and cannot give opacity the database does not
     * have. auth_token_credentials.credential_id is varchar(191), so a proof
     * can carry a non-canonical id the credential table cannot match. Filed as
     * #19; these tests use canonical decimal ids because that is what every
     * driver actually writes.
     */

    /** @param list<string> $credentialIds */
    private function tokenCiting(string $tokenKey, array $credentialIds, ActorKind $actor = ActorKind::Human): void
    {
        $factors = [];
        foreach ($credentialIds as $index => $credentialId) {
            $factors[] = new SatisfiedFactor(
                $index === 0 ? 'password' : 'totp',
                $credentialId,
                $index === 0 ? FactorKind::Knowledge : FactorKind::Possession,
                $index === 0 ? FactorStrength::Knowledge : FactorStrength::Possession,
                false, false, false, null,
                new DateTimeImmutable('2026-08-13T10:00:00+00:00'),
            );
        }

        app(TokenAssuranceRecord::class)->store(
            'sanctum', $tokenKey, $this->subject(), null, $actor, $factors,
        );
    }

    /** @return list<string> */
    private function survivingTokens(): array
    {
        $keys = DB::table('auth_token_assurances')->orderBy('token_key')->pluck('token_key')->all();

        return array_values(array_map(stringValue(...), $keys));
    }

    private function mutation(RecordingIssuer $issuer): CredentialMutation
    {
        app()->instance(TokenIssuerRegistry::class, new TokenIssuerRegistry([$issuer]));

        return app(CredentialMutation::class);
    }

    #[Test]
    public function adding_a_credential_preserves_every_existing_token(): void
    {
        /*
         * The rule that makes strengthening an account safe. An existing
         * token's proof cites the credentials actually used; a NEW credential
         * falsifies none of them, so nothing recorded became untrue.
         *
         * Without this, enrolling TOTP would log out every API client the
         * subject has — punishing exactly the behaviour the package exists to
         * encourage.
         */
        $this->tokenCiting('live-token', ['101']);
        $issuer = new RecordingIssuer('sanctum');

        /*
         * A REAL enrollment write, not a flag. "Nothing was revoked" is also
         * true of a facade that did nothing at all, so the additive path has to
         * prove it actually ran and committed something — otherwise this test
         * passes in the complete absence of the feature and reads as coverage.
         */
        $this->mutation($issuer)->additive($this->subject(), static function (ConnectionInterface $connection): void {
            $connection->table('auth_credentials')->insert([
                'id' => 5150,
                'user_id' => 7,
                'type' => 'totp',
                'secret' => 'JBSWY3DPEHPK3PXP',
                'strength' => 'possession',
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        });

        self::assertSame(1, DB::table('auth_credentials')->where('id', 5150)->count());
        self::assertSame(['live-token'], $this->survivingTokens());
        self::assertSame([], $issuer->revoked);
    }

    #[Test]
    public function disabling_a_credential_revokes_only_the_tokens_whose_proof_cites_it(): void
    {
        /*
         * Precise, not subject-wide. A token proved with a DIFFERENT credential
         * is untouched by this one being removed, and revoking it anyway would
         * make every credential change a full logout.
         */
        $this->tokenCiting('cites-one', ['101']);
        $this->tokenCiting('cites-two', ['102']);
        $this->tokenCiting('cites-both', ['101', '102']);
        $issuer = new RecordingIssuer('sanctum');

        $this->mutation($issuer)->revoking($this->subject(), ['101'], static fn (ConnectionInterface $connection) => null);

        self::assertSame(['cites-two'], $this->survivingTokens());
        // Lexical order: 'cites-both' sorts before 'cites-one'. The list is
        // sorted because the facade's revocation order is not contracted; only
        // the SET is.
        self::assertSame(['cites-both', 'cites-one'], $this->sorted($issuer->revoked));

        /*
         * The mappings go with the record. Deleting the assurance and leaving
         * auth_token_credentials behind would strand credential ids -- the more
         * sensitive column of the pair -- with nothing pointing at them, which
         * is the retention problem Task 5a closed, reopened here.
         */
        $mapped = DB::table('auth_token_credentials')->orderBy('token_key')->pluck('token_key')->all();
        self::assertSame(['cites-two'], array_values(array_unique(array_map(stringValue(...), $mapped))));
    }

    #[Test]
    public function a_token_is_revoked_by_any_credential_in_its_proof(): void
    {
        /*
         * A multi-factor proof is only as live as its weakest surviving part.
         * If ANY credential it cites is gone, the proof no longer describes
         * something that could be re-performed, so the token must not keep
         * asserting it.
         */
        $this->tokenCiting('two-factor', ['101', '102']);
        $issuer = new RecordingIssuer('sanctum');

        $this->mutation($issuer)->revoking($this->subject(), ['102'], static fn (ConnectionInterface $connection) => null);

        self::assertSame([], $this->survivingTokens());
        self::assertSame(['two-factor'], $issuer->revoked);
    }

    #[Test]
    public function regenerating_a_credential_set_revokes_once_not_twice(): void
    {
        /*
         * Recovery-code regeneration disables ten credentials and creates ten
         * more. Treated as separate mutations it would revoke on the removal
         * and revoke again on the creation — the user punished twice for one
         * action, and the second pass revoking tokens that the first pass had
         * already replaced.
         *
         * One replacement operation: the removal revokes, the creation inside
         * the same mutation does not.
         */
        $this->tokenCiting('old-codes', ['201']);
        $issuer = new RecordingIssuer('sanctum');
        $created = [];

        $this->mutation($issuer)->revoking(
            $this->subject(),
            ['201', '202'],
            function (ConnectionInterface $connection) use (&$created): void {
                // The creation half of the replacement, inside the same mutation.
                $created[] = 'code-11';
            },
        );

        self::assertSame([], $this->survivingTokens());
        self::assertSame(['old-codes'], $issuer->revoked);
        self::assertSame(['code-11'], $created);
    }

    #[Test]
    public function a_password_change_sweeps_this_subjects_human_tokens(): void
    {
        $this->tokenCiting('human-a', ['101']);
        $this->tokenCiting('human-b', ['109']);
        $issuer = new RecordingIssuer('sanctum');

        $this->mutation($issuer)->subjectWide($this->subject(), static fn (ConnectionInterface $connection) => null);

        self::assertSame([], $this->survivingTokens());
        self::assertSame(['human-a', 'human-b'], $this->sorted($issuer->revoked));
    }

    #[Test]
    public function a_subject_wide_sweep_leaves_machine_tokens_untouched(): void
    {
        /*
         * Contract, not an implementation convention. A machine token's
         * authority never came from the password, and Vouch does not issue or
         * authorize machine tokens in this phase — `Vouch::issueToken` refuses
         * machine grants outright. Revoking one on a password change would be
         * collateral behaviour outside the package's ownership boundary, and it
         * would break service-to-service traffic during a routine user action.
         *
         * An explicit machine-token revocation API is #9's, deliberately not
         * this task's.
         */
        $this->tokenCiting('human-token', ['101'], ActorKind::Human);

        /*
         * Empty factors, because TokenAssuranceRecord refuses a machine record
         * that carries human ones -- "A machine token cannot carry human
         * assurance factors". A machine record legitimately has no proof; that
         * is what makes actor_kind the only thing the sweep can filter on.
         */
        app(TokenAssuranceRecord::class)->store(
            'sanctum', 'machine-token', $this->subject(), null, ActorKind::Machine, [],
        );
        $issuer = new RecordingIssuer('sanctum');

        $this->mutation($issuer)->subjectWide($this->subject(), static fn (ConnectionInterface $connection) => null);

        self::assertSame(['machine-token'], $this->survivingTokens());
        self::assertSame(['human-token'], $issuer->revoked);
    }

    #[Test]
    public function a_precise_revocation_cannot_reach_a_machine_record(): void
    {
        /*
         * Defense in depth, and labelled as such: this state is NOT reachable
         * through the package. TokenAssuranceRecord refuses a machine record
         * carrying factors -- "A machine token cannot carry human assurance
         * factors" -- so a machine row referencing a credential can only exist
         * if something outside Vouch wrote it.
         *
         * That is precisely the case where Vouch must not act. The row is
         * inserted directly here because the legitimate API cannot produce it,
         * and the assertion is that a credential-scoped revocation still does
         * not touch a machine actor.
         */
        $this->tokenCiting('human-token', ['101'], ActorKind::Human);

        DB::table('auth_token_assurances')->insert([
            'issuer_key' => 'sanctum',
            'token_key' => 'machine-token',
            'subject_key' => $this->subject()->render(),
            'tenant_id' => null,
            'actor_kind' => ActorKind::Machine->value,
            'acr' => null,
            'assurance_proof' => null,
            'weakest_satisfied_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('auth_token_credentials')->insert([
            'issuer_key' => 'sanctum',
            'token_key' => 'machine-token',
            'credential_id' => '101',
        ]);

        $issuer = new RecordingIssuer('sanctum');

        $this->mutation($issuer)->revoking($this->subject(), ['101'], static fn (ConnectionInterface $connection) => null);

        self::assertSame(['machine-token'], $this->survivingTokens());
        self::assertSame(['human-token'], $issuer->revoked);
    }

    #[Test]
    public function another_subjects_tokens_are_never_touched(): void
    {
        app(TokenAssuranceRecord::class)->store(
            'sanctum', 'other-subject-token',
            SubjectKey::of(configuredUserProvider(), '8'), null, ActorKind::Human,
            [new SatisfiedFactor('password', '101', FactorKind::Knowledge, FactorStrength::Knowledge,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'))],
        );
        $this->tokenCiting('mine', ['101']);
        $issuer = new RecordingIssuer('sanctum');

        // Same credential id under a different subject: ids are opaque and are
        // not a cross-subject identity.
        $this->mutation($issuer)->revoking($this->subject(), ['101'], static fn (ConnectionInterface $connection) => null);

        self::assertSame(['other-subject-token'], $this->survivingTokens());
        self::assertSame(['mine'], $issuer->revoked);
    }

    #[Test]
    public function vouch_invalidation_is_committed_before_the_driver_is_asked(): void
    {
        /*
         * The ordering the whole protocol rests on. Vouch's own record is what
         * actually stops authorization: the gate reads it, and a token with no
         * assurance record is refused. Driver deletion is best-effort cleanup
         * of someone else's storage.
         *
         * Asserted by having the issuer LOOK at the table while it is being
         * revoked. If the record is still there when revoke() runs, the two
         * were done in the wrong order, and a driver failure could then roll
         * back the invalidation and resurrect authorization.
         */
        if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
            && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
            self::markTestSkipped('Proving the invalidation COMMITTED needs a second connection.');
        }

        $this->tokenCiting('doomed', ['101']);
        $issuer = new RecordingIssuer('sanctum');
        $issuer->onRevoke = static function (): array {
            /*
             * Read on a SEPARATE physical connection. A same-connection read
             * always sees its own uncommitted writes, so it could not tell a
             * committed invalidation from one still inside an open transaction
             * -- which is the entire claim. Copied from the default rather than
             * invented, so the matrix points it at the engine under test.
             */
            config(['database.connections.mutation_probe' => Config::array(
                'database.connections.' . Config::string('database.default'),
            )]);

            return [
                'assurances' => DB::connection('mutation_probe')
                    ->table('auth_token_assurances')->where('token_key', 'doomed')->count(),
                'mappings' => DB::connection('mutation_probe')
                    ->table('auth_token_credentials')->where('token_key', 'doomed')->count(),
            ];
        };

        $this->mutation($issuer)->revoking($this->subject(), ['101'], static fn (ConnectionInterface $connection) => null);

        self::assertSame([['assurances' => 0, 'mappings' => 0]], $issuer->observed);
    }

    #[Test]
    public function a_driver_failure_leaves_authorization_already_invalidated(): void
    {
        /*
         * Fail closed. The driver's token row may survive an unreachable
         * driver, but the assurance record is already gone and committed, so
         * the gate refuses the token regardless. The failure is reported for
         * out-of-band retry rather than rolled back — rolling back would
         * restore the very authorization the mutation was performed to remove.
         */
        $this->tokenCiting('doomed', ['101']);
        $issuer = new RecordingIssuer('sanctum', throwsOnRevoke: new RuntimeException('driver unreachable'));

        $result = $this->mutation($issuer)->revoking($this->subject(), ['101'], static fn (ConnectionInterface $connection) => null);

        self::assertSame([], $this->survivingTokens());
        self::assertNotSame([], $result->driverFailures);

        /*
         * A failure a host can ACT on. Vouch does not schedule retries of its
         * own -- there is no queue, no durable work item, and inventing one
         * here would be a second scheduled subsystem nobody asked for. What it
         * owes the caller is the identity needed to retry: which issuer, and
         * which token. A bare message string is a log line, not a work item.
         */
        $failure = $result->driverFailures[0];
        self::assertSame('sanctum', $failure->issuerKey);
        self::assertSame('doomed', $failure->tokenKey);
        self::assertStringContainsString('driver unreachable', $failure->message);
    }

    #[Test]
    public function a_host_retry_after_a_driver_failure_cannot_restore_authorization(): void
    {
        /*
         * The other half of "retried out of band". Vouch's record is already
         * gone and committed, so a later retry -- successful or not -- reaches
         * only the driver's own storage. The property that matters is that
         * nothing on the retry path can bring the assurance record back and
         * re-authorize a token the mutation removed.
         */
        $this->tokenCiting('doomed', ['101']);
        $failing = new RecordingIssuer('sanctum', throwsOnRevoke: new RuntimeException('driver unreachable'));

        $result = $this->mutation($failing)->revoking($this->subject(), ['101'], static fn (ConnectionInterface $connection) => null);
        self::assertSame([], $this->survivingTokens());

        // The host retries the reported work item against a healthy driver.
        $healthy = new RecordingIssuer('sanctum');
        $healthy->revoke($result->driverFailures[0]->tokenKey);

        self::assertSame(['doomed'], $healthy->revoked);
        self::assertSame([], $this->survivingTokens());
        self::assertSame(0, DB::table('auth_token_credentials')->count());
    }

    #[Test]
    public function a_nested_mutation_defers_the_driver_until_the_caller_commits(): void
    {
        /*
         * The construction that replaced a prohibition. The facade used to
         * refuse a caller's transaction, because joining one left Vouch's
         * invalidation uncommitted when the driver was asked — the ordering the
         * whole protocol rests on. Refusing cost 247 pre-existing tests, since
         * RefreshDatabase wraps every one of them.
         *
         * Deferring the driver call to the OUTERMOST commit gives the same
         * ordering by construction, under any nesting, and asks nothing of the
         * caller. This test is what stops it regressing to either of the two
         * worse shapes: a synchronous call inside the caller's transaction
         * (wrong order), or a refusal (unusable).
         */
        $this->tokenCiting('doomed', ['101']);
        $issuer = new RecordingIssuer('sanctum', throwsOnRevoke: new RuntimeException('driver unreachable'));
        $mutation = $this->mutation($issuer);
        $result = null;

        DB::transaction(function () use ($mutation, $issuer, &$result): void {
            $result = $mutation->revoking($this->subject(), ['101'], static fn (ConnectionInterface $connection) => null);

            // Inside the caller's transaction the driver has NOT been asked:
            // Vouch's invalidation is not committed yet, so asking now would be
            // exactly the reversal this defers to avoid.
            self::assertSame([], $issuer->attempted);
            self::assertSame([], $result->driverFailures);
        });

        // After the caller's commit it has been asked, and its failure recorded
        // on the same result — which is why that object is not readonly.
        self::assertInstanceOf(CredentialMutationResult::class, $result);
        self::assertSame(['doomed'], $issuer->attempted);
        self::assertCount(1, $result->driverFailures);
        self::assertSame('doomed', $result->driverFailures[0]->tokenKey);
        self::assertSame([], $this->survivingTokens());
    }

    #[Test]
    public function a_nested_driver_failure_cannot_break_the_callers_transaction(): void
    {
        /*
         * The deferred call runs during the CALLER's commit. A throw escaping
         * there would turn best-effort driver cleanup into an application-level
         * failure, and would do it at the worst possible moment — after the
         * caller believed its work was done.
         */
        $this->tokenCiting('doomed', ['101']);
        $issuer = new RecordingIssuer('sanctum', throwsOnRevoke: new RuntimeException('driver unreachable'));
        $mutation = $this->mutation($issuer);

        $completed = DB::transaction(function () use ($mutation): string {
            $mutation->revoking($this->subject(), ['101'], static fn (ConnectionInterface $connection) => null);

            return 'the caller finished';
        });

        self::assertSame('the caller finished', $completed);
        self::assertSame(0, DB::transactionLevel());
        self::assertSame([], $this->survivingTokens());
    }

    #[Test]
    public function one_driver_failure_does_not_strand_the_other_tokens(): void
    {
        $this->tokenCiting('first', ['101']);
        $this->tokenCiting('second', ['101']);
        $issuer = new RecordingIssuer('sanctum', throwsOnRevoke: new RuntimeException('down'), throwOnCall: 1);

        $this->mutation($issuer)->revoking($this->subject(), ['101'], static fn (ConnectionInterface $connection) => null);

        self::assertSame([], $this->survivingTokens());
        self::assertCount(2, $issuer->attempted);
        // The failing driver call must not abandon the rest of the batch: both
        // records are invalidated regardless of which driver call threw.
        self::assertSame(0, DB::table('auth_token_credentials')->count());
    }

    #[Test]
    public function revoking_a_credential_no_token_cites_is_not_an_error(): void
    {
        /*
         * The ordinary case for a subject with no tokens at all. A credential
         * mutation must not fail because nothing referenced the credential.
         */
        $issuer = new RecordingIssuer('sanctum');

        $result = $this->mutation($issuer)->revoking($this->subject(), ['999'], static fn (ConnectionInterface $connection) => null);

        self::assertSame([], $issuer->revoked);
        self::assertSame(0, $result->revoked);
    }

    #[Test]
    public function the_mutation_is_idempotent_when_retried(): void
    {
        /*
         * Out-of-band retry after a driver failure must converge rather than
         * error on the second pass, when Vouch's record is already gone.
         */
        $this->tokenCiting('doomed', ['101']);
        $issuer = new RecordingIssuer('sanctum');

        $this->mutation($issuer)->revoking($this->subject(), ['101'], static fn (ConnectionInterface $connection) => null);
        $second = $this->mutation($issuer)->revoking($this->subject(), ['101'], static fn (ConnectionInterface $connection) => null);

        self::assertSame([], $this->survivingTokens());
        self::assertSame(0, $second->revoked);
    }

    #[Test]
    public function the_write_receives_the_connection_the_mutation_owns(): void
    {
        /*
         * The facade owns the connection, the transaction and the locks, so the
         * caller's write must happen ON that connection. Handing the closure
         * nothing and letting it reach for the default would let a writer take
         * the locks on one connection and write on another — serialized against
         * nothing, and invisible in every assertion about the end state.
         */
        $this->tokenCiting('doomed', ['101']);
        $issuer = new RecordingIssuer('sanctum');
        $received = null;
        $levelDuringWrite = null;

        $this->mutation($issuer)->revoking(
            $this->subject(),
            ['101'],
            function (ConnectionInterface $connection) use (&$received, &$levelDuringWrite): void {
                $received = $connection;
                $levelDuringWrite = $connection->transactionLevel();
            },
        );

        self::assertInstanceOf(ConnectionInterface::class, $received);
        self::assertGreaterThan(0, $levelDuringWrite);
    }

    #[Test]
    public function a_rolled_back_write_leaves_the_credential_and_the_tokens_together(): void
    {
        /*
         * The write and the invalidation are ONE decision, and a real write is
         * needed to prove it: a closure that only sets a flag cannot show that
         * a rollback restored anything.
         *
         * Here the closure genuinely disables a credential row and then fails.
         * Afterwards the credential must be live again AND the token must still
         * be there — a partial outcome in either direction is the bug. A
         * surviving token whose credential was disabled would authorize against
         * a credential that no longer exists; a revoked token whose credential
         * came back would log someone out over a mutation that never happened.
         */
        DB::table('auth_credentials')->insert([
            'id' => 4242,
            'user_id' => 7,
            'type' => 'password',
            'secret' => 'hashed',
            'strength' => 'knowledge',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $this->tokenCiting('live', ['4242']);
        $issuer = new RecordingIssuer('sanctum');

        try {
            $this->mutation($issuer)->revoking(
                $this->subject(),
                ['4242'],
                static function (ConnectionInterface $connection): void {
                    $connection->table('auth_credentials')
                        ->where('id', 4242)->update(['disabled_at' => now()]);

                    throw new RuntimeException('the credential write failed');
                },
            );
            self::fail('The mutation should surface a failed credential write.');
        } catch (RuntimeException $exception) {
            self::assertSame('the credential write failed', $exception->getMessage());
        }

        self::assertNull(DB::table('auth_credentials')->where('id', 4242)->value('disabled_at'));
        self::assertSame(['live'], $this->survivingTokens());
        self::assertSame(1, DB::table('auth_token_credentials')->where('token_key', 'live')->count());
        self::assertSame([], $issuer->revoked);
    }

    #[Test]
    public function a_failing_credential_write_revokes_nothing(): void
    {
        /*
         * The write and the invalidation are one atomic decision. If the
         * credential change did not happen, the tokens that depended on it are
         * still valid, and revoking them would log a user out over a mutation
         * that was rolled back.
         */
        $this->tokenCiting('live', ['101']);
        $issuer = new RecordingIssuer('sanctum');

        try {
            $this->mutation($issuer)->revoking($this->subject(), ['101'], static function (): void {
                throw new RuntimeException('the credential write failed');
            });
            self::fail('The mutation should surface a failed credential write.');
        } catch (RuntimeException $exception) {
            self::assertSame('the credential write failed', $exception->getMessage());
        }

        self::assertSame(['live'], $this->survivingTokens());
        self::assertSame([], $issuer->revoked);
    }

    /**
     * @param list<string> $values
     * @return list<string>
     */
    private function sorted(array $values): array
    {
        sort($values);

        return $values;
    }
}
