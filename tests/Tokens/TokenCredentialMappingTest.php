<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use DateTimeImmutable;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 2 — the credential mapping, which is what makes revocation reach.
 *
 * The mapping exists so a credential disable can find every token that
 * credential helped authorize, without a JSON containment scan on a revocation
 * path. Task 5 performs the revocation; Task 2 must guarantee the mapping is
 * COMPLETE, because a sweep can only be as correct as the rows it reads.
 *
 * Completeness is the whole point since addendum §3's amendment: the proof is
 * every factor satisfied in the attempt, so the mapping must carry every
 * credential in it — not the subset some policy branch happened to need.
 */
final class TokenCredentialMappingTest extends TestCase
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
    }

    private function factor(string $id, string $credentialId, FactorStrength $strength): SatisfiedFactor
    {
        return new SatisfiedFactor($id, $credentialId, FactorKind::Knowledge, $strength,
            false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'));
    }

    private function subject(): SubjectKey
    {
        return SubjectKey::of((new TokenUser)->getMorphClass(), 7);
    }

    /** @param list<SatisfiedFactor> $factors */
    private function store(array $factors, string $key = '42'): void
    {
        app(TokenAssuranceRecord::class)
            ->store('sanctum', $key, $this->subject(), null, ActorKind::Human, $factors);
    }

    /** @return list<string> */
    private function mapped(string $key = '42'): array
    {
        return array_map(
            static fn (mixed $v): string => (string) $v,
            DB::table('auth_token_credentials')
                ->where('issuer_key', 'sanctum')->where('token_key', $key)
                ->orderBy('credential_id')->pluck('credential_id')->all(),
        );
    }

    #[Test]
    public function every_credential_in_the_proof_is_mapped(): void
    {
        /*
         * THE completeness rule. An implementation mapping only the strongest
         * factor, or only the one that reached the required level, passes every
         * other test in this file and silently leaves the password unmapped —
         * so disabling the password would fail to revoke a token the password
         * helped authorize.
         */
        $this->store([
            $this->factor('password', 'cred-pw', FactorStrength::Knowledge),
            $this->factor('totp', 'cred-totp', FactorStrength::Possession),
        ]);

        self::assertSame(['cred-pw', 'cred-totp'], $this->mapped());
    }

    #[Test]
    public function two_factors_sharing_one_credential_map_once(): void
    {
        /*
         * A user-verified passkey is two factors on ONE authenticator. Mapping
         * it twice would violate the table's uniqueness and, if that constraint
         * were ever relaxed, make a revocation sweep double-count.
         */
        $this->store([
            $this->factor('passkey', 'cred-1', FactorStrength::Possession),
            $this->factor('passkey_uv', 'cred-1', FactorStrength::PossessionStrong),
        ]);

        self::assertSame(['cred-1'], $this->mapped());
    }

    /*
     * A "deterministic write order" test stood here and was removed rather than
     * repaired. It sorted the rows on READ, so both orderings passed it, and
     * database row order is not a locking guarantee in any case. The property
     * it was reaching for — that concurrent issuance and revocation acquire
     * credential locks in one order and cannot deadlock — is a property of the
     * lock acquisition, and belongs to Task 3's contract where the locks exist.
     */

    #[Test]
    public function re_recording_a_token_replaces_its_mappings(): void
    {
        /*
         * A stale mapping is worse than a missing one: it makes a revocation
         * sweep revoke a token on the strength of a credential that is no longer
         * part of its proof, which reads to the holder as a random logout.
         */
        $this->store([
            $this->factor('password', 'cred-pw', FactorStrength::Knowledge),
            $this->factor('totp', 'cred-totp', FactorStrength::Possession),
        ]);
        $this->store([$this->factor('password', 'cred-pw', FactorStrength::Knowledge)]);

        self::assertSame(['cred-pw'], $this->mapped());
    }

    #[Test]
    public function a_machine_token_maps_no_credentials(): void
    {
        // No human factors, so nothing to revoke it through. A mapping here
        // would attach a machine token to a person's credential lifecycle.
        app(TokenAssuranceRecord::class)
            ->store('sanctum', 'svc-1', $this->subject(), null, ActorKind::Machine, []);

        self::assertSame([], $this->mapped('svc-1'));
    }

    #[Test]
    public function mappings_are_removed_with_the_record_they_describe(): void
    {
        /*
         * Orphaned mappings accumulate and, worse, keep answering "which tokens
         * does this credential authorize?" with tokens that no longer exist —
         * so a sweep reports work it did not do.
         */
        $this->store([$this->factor('password', 'cred-pw', FactorStrength::Knowledge)]);

        app(TokenAssuranceRecord::class)->forget('sanctum', '42');

        self::assertSame([], $this->mapped());
        self::assertSame(0, DB::table('auth_token_assurances')->count());
    }

    #[Test]
    public function forgetting_one_token_leaves_another_issuers_mappings_alone(): void
    {
        // Composite scoping on the delete path, where a missed predicate is
        // silent: the sweep succeeds and takes an unrelated token with it.
        $this->store([$this->factor('password', 'cred-pw', FactorStrength::Knowledge)]);
        app(TokenAssuranceRecord::class)
            ->store('passport', '42', $this->subject(), null, ActorKind::Human, [$this->factor('password', 'cred-pw', FactorStrength::Knowledge)]);

        app(TokenAssuranceRecord::class)->forget('sanctum', '42');

        self::assertSame(1, DB::table('auth_token_credentials')->where('issuer_key', 'passport')->count());
        self::assertSame(1, DB::table('auth_token_assurances')->where('issuer_key', 'passport')->count());
    }
}
