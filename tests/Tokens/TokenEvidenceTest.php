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
         * `usable` is the issuer's verdict on lifecycle — Vouch does not own
         * token expiry or revocation and must not second-guess it. A stored
         * proof remains a true record of a past login, so the refusal comes
         * from the token's state, never from the evidence being absent.
         *
         * NO SHIPPED ISSUER PRODUCES THIS. Measured against Sanctum: an expired
         * token and a revoked one both make resolveForRequest() return null, so
         * neither ever reaches this adapter, and SanctumTokenIssuer only ever
         * constructs usable: true. Sanctum deletes on revoke — there is no
         * revoked_at — so the state is not recoverable at any layer (addendum
         * §3b).
         *
         * The path is kept as a seam for third-party issuers whose lifecycle
         * model CAN report unusability: Passport, or a host driver over a table
         * that marks rather than deletes. Recorded as unreachable-today so a
         * later reader does not mistake it for a live branch, the same way §3a
         * records that aal3 is unsatisfiable with the shipped vocabulary.
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

    #[Test]
    public function a_human_record_refuses_an_empty_or_recovery_only_proof(): void
    {
        /*
         * The actor-specific stored invariant, which the machine tests alone do
         * not pin. A human record with no factors is a token that proved
         * nothing while claiming a person authorized it — and since a machine
         * record legitimately has none, an implementation could satisfy every
         * other test by writing humans the same way.
         */
        $recovery = new SatisfiedFactor('recovery_code', 'cred-r', FactorKind::Knowledge, FactorStrength::Recovery,
            false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'));

        foreach ([[], [$recovery]] as $factors) {
            try {
                $this->record()->store('sanctum', 'x', $this->subject(), null, ActorKind::Human, $factors);
                self::fail('A human record accepted a proof that proves nothing.');
            } catch (\Throwable $e) {
                self::assertInstanceOf(\Fissible\Vouch\Assurance\MalformedEvidence::class, $e);
            }
        }
    }

    #[Test]
    public function a_machine_record_refuses_human_factors(): void
    {
        /*
         * The other direction. A machine token carrying a person's factors
         * would tie a service credential to a human's credential lifecycle and,
         * worse, make actor_kind a label rather than a fact about the row.
         */
        $this->expectException(\Fissible\Vouch\Assurance\MalformedEvidence::class);

        $this->record()->store('sanctum', 'svc-2', $this->subject(), null, ActorKind::Machine, $this->proof());
    }

    #[Test]
    public function the_stored_anchor_is_the_proofs_oldest_timestamp(): void
    {
        /*
         * weakest_satisfied_at is non-null by schema, which means an
         * implementation MUST put something there — and for a machine record,
         * with no factors, there is no authentication instant to put. Pin the
         * meaning for both actor kinds rather than leaving a fabricated
         * issuance timestamp to satisfy the constraint silently.
         */
        $this->stored();

        self::assertSame(
            '2026-08-13 10:00:00',
            substr((string) DB::table('auth_token_assurances')->value('weakest_satisfied_at'), 0, 19),
        );
    }

    #[Test]
    public function a_machine_record_does_not_fabricate_an_authentication_instant(): void
    {
        /*
         * A machine token has no authentication evidence, so any value in the
         * recency column would be a fiction — and a max_age requirement reading
         * it would be answering a question that was never asked. The record
         * must be storable without inventing one.
         */
        $this->record()->store('sanctum', 'svc-1', $this->subject(), null, ActorKind::Machine, []);

        $anchor = DB::table('auth_token_assurances')->where('token_key', 'svc-1')->value('weakest_satisfied_at');

        self::assertNull($anchor);
    }

    #[Test]
    public function it_refuses_a_record_whose_stored_json_is_not_decodable(): void
    {
        // Distinct from a well-formed envelope with a bad factor: a truncated
        // write, or a column that lost its cast, produces a string that is not
        // JSON at all.
        $this->stored();
        DB::table('auth_token_assurances')->update(['assurance_proof' => '{"subject":']);

        $read = $this->record()->read(new ResolvedToken('sanctum', '42', $this->subject(), true));

        self::assertNull($read->evidence);
        self::assertSame(AssuranceReason::ProofMalformed, $read->reason);
    }

    #[Test]
    public function it_refuses_a_human_record_with_no_recency_anchor(): void
    {
        /*
         * The read-side half of the actor-scoped invariant. The column is
         * nullable so machine records can exist, which means a human row CAN be
         * hand-edited or half-written into a state its proof contradicts.
         * Authorization must refuse it rather than compare a requirement
         * against a missing instant.
         */
        $this->stored();
        DB::table('auth_token_assurances')->update(['weakest_satisfied_at' => null]);

        $read = $this->record()->read(new ResolvedToken('sanctum', '42', $this->subject(), true));

        self::assertNull($read->evidence);
        self::assertSame(AssuranceReason::ProofMalformed, $read->reason);
    }

    #[Test]
    public function the_stored_level_is_a_projection_and_never_an_authorization_input(): void
    {
        /*
         * Same rule as auth_sessions.acr, asserted the same way and in both
         * directions, because the token table is a fresh chance to make the
         * mistake Task 2a spent its existence removing.
         *
         * A record tampered UP must not authorize at the claimed level, and one
         * tampered DOWN must not cap what the proof actually derives — the
         * second is the half an implementation passes by accident while still
         * requiring the column to agree.
         */
        $this->stored();

        DB::table('auth_token_assurances')->update(['acr' => 'aal3']);
        $up = $this->record()->read(new ResolvedToken('sanctum', '42', $this->subject(), true))->evidence;

        DB::table('auth_token_assurances')->update(['acr' => 'aal1']);
        $down = $this->record()->read(new ResolvedToken('sanctum', '42', $this->subject(), true))->evidence;

        self::assertNotNull($up);
        self::assertNotNull($down);
        self::assertSame('aal2', $up->derivedAcr());
        self::assertSame('aal2', $down->derivedAcr());

        /*
         * And the DECISION, not merely the derived value. An implementation can
         * derive correctly here and still consult the stored column somewhere on
         * the way to a verdict — which is the failure this rule exists to stop,
         * and which the two assertions above cannot see.
         */
        $comparator = app(EvidenceComparator::class);
        $requirement = AssuranceRequirement::from('aal2');

        DB::table('auth_token_assurances')->update(['acr' => 'aal1']);
        $tamperedDown = $this->record()->read(new ResolvedToken('sanctum', '42', $this->subject(), true));

        DB::table('auth_token_assurances')->update(['acr' => 'aal3']);
        $tamperedUp = $this->record()->read(new ResolvedToken('sanctum', '42', $this->subject(), true));

        // The column said aal1; the proof says aal2, so aal2 is granted.
        self::assertSame(
            AssuranceOutcome::Sufficient,
            $comparator->compare($tamperedDown, $requirement, $this->clock(), null)->outcome,
        );
        // The column said aal3; the proof says aal2, so aal3 is refused.
        self::assertSame(
            AssuranceOutcome::InsufficientLevel,
            $comparator->compare($tamperedUp, AssuranceRequirement::from('aal3'), $this->clock(), null)->outcome,
        );
    }

    #[Test]
    public function storing_writes_the_projection_from_the_proof(): void
    {
        // The column has a writer from the first commit, so it cannot become
        // another assurance_facts: a column nobody writes, that a later reader
        // mistakes for authority.
        $this->stored();

        self::assertSame('aal2', DB::table('auth_token_assurances')->value('acr'));
    }
}
