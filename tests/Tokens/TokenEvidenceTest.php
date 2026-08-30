<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use DateTimeImmutable;
use Fissible\Vouch\Assurance\AssuranceOutcome;
use Fissible\Vouch\Assurance\AssuranceReason;
use Fissible\Vouch\Assurance\AssuranceRequirement;
use Fissible\Vouch\Assurance\EvidenceComparator;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\ResolvedToken;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Clock\ClockInterface;

/**
 * 2.4 Task 2 — the token adapter.
 *
 * The value-level rules (strict deserialization, the level lattice, recency
 * arithmetic, the four outcomes) belong to Task 2a and are NOT re-asserted here.
 * Repeating them would duplicate coverage and give the two surfaces a second
 * place to disagree. What is new is everything specific to a token: composite
 * identity, actor kind, and the refusals that only a token can produce.
 */
final class TokenEvidenceTest extends TestCase
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

    private function record(): TokenAssuranceRecord
    {
        return app(TokenAssuranceRecord::class);
    }

    private function clock(): ClockInterface
    {
        return new class implements ClockInterface {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable('2026-08-13T10:10:00+00:00');
            }
        };
    }

    private function stored(string $issuer = 'sanctum', string $key = '42', ?string $tenant = null): ResolvedToken
    {
        $this->record()->store($issuer, $key, $this->subject(), $tenant, ActorKind::Human, $this->proof());

        return new ResolvedToken($issuer, $key, $this->subject(), true);
    }

    #[Test]
    public function it_round_trips_a_stored_proof(): void
    {
        $evidence = $this->record()->read($this->stored())->evidence;

        self::assertNotNull($evidence);
        self::assertEquals($this->proof(), $evidence->factors);
        self::assertSame('aal2', $evidence->derivedAcr());
    }

    #[Test]
    public function it_reports_no_record_distinctly_from_malformed_data(): void
    {
        /*
         * The default-deny case, and the one an operator will see most. A token
         * Vouch never recorded is not corrupt and not weak — it simply predates
         * enrolment or was minted outside the issuance path. Collapsing it into
         * ProofMalformed would send someone hunting for corruption that is not
         * there; collapsing it into a weak level would invite a step-up that
         * cannot help.
         */
        $read = $this->record()->read(new ResolvedToken('sanctum', 'never-recorded', $this->subject(), true));

        self::assertNull($read->evidence);
        self::assertSame(AssuranceReason::NoAssuranceRecord, $read->reason);
    }

    #[Test]
    public function it_refuses_a_token_the_issuer_reported_unusable(): void
    {
        /*
         * `usable` is the issuer's verdict on revocation and expiry — Vouch does
         * not own token lifecycle and must not second-guess it. A stored proof
         * is still a true record of a past login, so the refusal has to come
         * from the token's state, never from the evidence being absent.
         */
        $token = $this->stored();
        $unusable = new ResolvedToken($token->issuerKey, $token->tokenKey, $token->subject, false);

        $read = $this->record()->read($unusable);

        self::assertNull($read->evidence);
        self::assertSame(AssuranceReason::TokenUnusable, $read->reason);
        // The record itself survives: revocation is not deletion, and an audit
        // trail that erased the proof would lose why the token was ever trusted.
        self::assertSame(1, DB::table('auth_token_assurances')->count());
    }

    #[Test]
    public function it_refuses_a_record_whose_subject_is_not_the_bearer(): void
    {
        /*
         * The record is found by (issuer, token), while the proof carries its own
         * subject — two identities nothing forces to agree. A token whose record
         * names user 8, presented by user 7, must refuse rather than hand the
         * bearer an assurance level established for somebody else.
         */
        $this->record()->store('sanctum', '42', $this->subject(8), null, ActorKind::Human, $this->proof());

        $read = $this->record()->read(new ResolvedToken('sanctum', '42', $this->subject(7), true));

        self::assertNull($read->evidence);
        self::assertSame(AssuranceReason::SubjectMismatch, $read->reason);
    }

    #[Test]
    public function it_does_not_read_one_issuers_record_for_another(): void
    {
        // Composite identity, exercised through the adapter rather than the
        // schema: two issuers minting key 42 must not see each other's proof.
        $this->stored('sanctum', '42');

        $read = $this->record()->read(new ResolvedToken('passport', '42', $this->subject(), true));

        self::assertNull($read->evidence);
        self::assertSame(AssuranceReason::NoAssuranceRecord, $read->reason);
    }

    #[Test]
    public function a_machine_token_carries_no_human_factors_and_satisfies_no_level(): void
    {
        /*
         * actor_kind is an actor CLASS, not a rung on the assurance ladder. A
         * machine token has no human evidence at all, so it can neither satisfy
         * an AAL requirement nor be stepped up to one — answering it with a
         * challenge would invite a machine to present a factor it does not have.
         */
        $this->record()->store('sanctum', 'svc-1', $this->subject(), null, ActorKind::Machine, []);

        $read = $this->record()->read(new ResolvedToken('sanctum', 'svc-1', $this->subject(), true));

        self::assertNull($read->evidence);
        self::assertSame(AssuranceReason::MachineActor, $read->reason);

        $comparison = app(EvidenceComparator::class)->compare(
            $read, AssuranceRequirement::from('aal1'), $this->clock(), null,
        );

        self::assertSame(AssuranceOutcome::InvalidEvidence, $comparison->outcome);
        self::assertSame(AssuranceReason::MachineActor, $comparison->reason);
    }

    #[Test]
    public function a_machine_token_is_recorded_as_machine_rather_than_as_weak_human(): void
    {
        // Stored shape, because the refusal above would also pass for an
        // implementation that recorded machines as humans with an empty proof —
        // and Task 4 routes opt in by naming the actor class.
        $this->record()->store('sanctum', 'svc-1', $this->subject(), null, ActorKind::Machine, []);

        self::assertSame('machine', DB::table('auth_token_assurances')->value('actor_kind'));
    }

    #[Test]
    public function it_refuses_a_record_whose_stored_proof_is_corrupt(): void
    {
        $this->stored();
        DB::table('auth_token_assurances')->update([
            'assurance_proof' => json_encode(['subject' => $this->subject()->render(), 'factors' => [['factor_id' => 'password']]]),
        ]);

        $read = $this->record()->read(new ResolvedToken('sanctum', '42', $this->subject(), true));

        self::assertNull($read->evidence);
        self::assertSame(AssuranceReason::ProofMalformed, $read->reason);
    }

    #[Test]
    public function it_persists_the_tenant_the_proof_was_minted_under(): void
    {
        $evidence = $this->record()->read($this->stored(tenant: 'acme'))->evidence;

        self::assertNotNull($evidence);
        self::assertSame('acme', $evidence->tenantId);
    }

    #[Test]
    public function storing_the_same_token_twice_replaces_rather_than_duplicates(): void
    {
        /*
         * Re-issuance for one token key must not leave two records. Which one a
         * reader picked would be arbitrary, and the loser would still be
         * consulted by any query that did not order deterministically.
         */
        $this->stored();
        $this->record()->store('sanctum', '42', $this->subject(), null, ActorKind::Human, [$this->proof()[0]]);

        $evidence = $this->record()->read(new ResolvedToken('sanctum', '42', $this->subject(), true))->evidence;

        self::assertSame(1, DB::table('auth_token_assurances')->count());
        self::assertNotNull($evidence);
        self::assertSame('aal1', $evidence->derivedAcr());
    }
}
