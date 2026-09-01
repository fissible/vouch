<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Database;

use Fissible\Vouch\Assurance\AssuranceOutcome;
use Fissible\Vouch\Assurance\AssuranceReason;
use Fissible\Vouch\Assurance\AssuranceRequirement;
use Fissible\Vouch\Assurance\EvidenceComparator;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Kernel\Assurance\NistAssuranceVocabulary;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\SessionEvidence;
use Fissible\Vouch\Tests\Support\Assurance\CappingVocabulary;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ResolvedToken;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Test;
use Psr\Clock\ClockInterface;

/**
 * Issue #10 — the stored `acr` column is a projection, not an input.
 *
 * EvidenceComparator has always re-derived from the persisted factors, so this
 * is not new behaviour; it is behaviour nothing described. Making the
 * vocabulary explicit is the moment the shortcut becomes tempting, because a
 * caller now has to hold a vocabulary to derive a name while a ready-made
 * string sits in the same row.
 */
final class AcrProjectionTest extends TestCase
{
    use RefreshDatabase;

    private function comparator(AssuranceVocabulary $vocabulary): EvidenceComparator
    {
        return new EvidenceComparator($vocabulary);
    }

    private function clock(): ClockInterface
    {
        return app(ClockInterface::class);
    }

    /** @param array<string, mixed> $proof */
    private function sessionRow(string $storedAcr, array $proof): AuthSession
    {
        $session = new AuthSession();
        $session->user_id = 7;
        $session->session_binding = 'session:' . $storedAcr . ':' . bin2hex(random_bytes(4));
        $session->amr = ['password'];
        $session->acr = $storedAcr;
        $session->assurance_proof = $proof;
        $session->weakest_satisfied_at = now();
        $session->save();

        return $session;
    }

    #[Test]
    public function a_stored_level_stronger_than_the_proof_grants_nothing(): void
    {
        /*
         * The row claims aal2; its factors derive aal1. If any path trusted the
         * column, this would authorize — which is the whole risk of storing a
         * name next to the evidence it was derived from.
         */
        $session = $this->sessionRow('aal2', sessionProof(7, 'aal1'));

        $comparison = $this->comparator(new NistAssuranceVocabulary())->compare(
            SessionEvidence::read($session),
            AssuranceRequirement::from('aal2'),
            $this->clock(),
            null,
        );

        self::assertSame(AssuranceOutcome::InsufficientLevel, $comparison->outcome);
    }

    #[Test]
    public function a_stored_level_weaker_than_the_proof_denies_nothing(): void
    {
        /*
         * The opposite direction, and it is the one that makes the pair
         * meaningful: an implementation that read the column and refused on any
         * disagreement would pass the test above and fail here.
         */
        $session = $this->sessionRow('aal1', sessionProof(7, 'aal2'));

        $comparison = $this->comparator(new NistAssuranceVocabulary())->compare(
            SessionEvidence::read($session),
            AssuranceRequirement::from('aal2'),
            $this->clock(),
            null,
        );

        self::assertSame(AssuranceOutcome::Sufficient, $comparison->outcome);
    }

    #[Test]
    public function an_authorization_decision_never_rewrites_the_projection(): void
    {
        $session = $this->sessionRow('aal2', sessionProof(7, 'aal2'));

        $this->comparator(new CappingVocabulary())->compare(
            SessionEvidence::read($session),
            AssuranceRequirement::from('aal2'),
            $this->clock(),
            null,
        );

        self::assertSame('aal2', $session->fresh()?->acr);
    }

    #[Test]
    public function a_stricter_vocabulary_refuses_fresh_access_and_leaves_history_intact(): void
    {
        /*
         * The migration scenario from the contract, end to end: a host binds a
         * vocabulary that caps at aal1. The old row still records what it was
         * called at the time, and a fresh aal2 requirement correctly fails.
         */
        $session = $this->sessionRow('aal2', sessionProof(7, 'aal2'));

        $comparison = $this->comparator(new CappingVocabulary())->compare(
            SessionEvidence::read($session),
            AssuranceRequirement::from('aal2'),
            $this->clock(),
            null,
        );

        self::assertSame(AssuranceOutcome::InsufficientLevel, $comparison->outcome);
        self::assertSame('aal2', $session->fresh()?->acr);
    }

    #[Test]
    public function drift_is_not_malformed_evidence(): void
    {
        /*
         * The refusal that must NOT happen. A reader treating a stale
         * projection as corruption would turn an intentional vocabulary
         * migration into a fleet-wide outage — every historical row rejected at
         * once, for a reason that describes none of them.
         */
        $session = $this->sessionRow('aal2', sessionProof(7, 'aal1'));

        $read = SessionEvidence::read($session);

        self::assertSame(AssuranceReason::Sufficient, $read->reason);
        self::assertNotNull($read->evidence);
    }

    #[Test]
    public function a_token_record_whose_projection_disagrees_is_still_readable(): void
    {
        /*
         * The same rule at the token reader, which needs stating separately
         * because that reader ALREADY refuses on a neighbouring column
         * disagreement: a proof whose tenant differs from the indexed tenant_id
         * returns ProofMalformed. An implementer adding an acr check three
         * lines below it would be following local precedent, and would turn
         * every historical row into malformed evidence the moment a host
         * changes vocabulary.
         */
        DB::table('auth_token_assurances')->insert([
            'issuer_key' => 'sanctum',
            'token_key' => 'drifted-token',
            'subject_key' => configuredUserProvider() . ':7',
            'tenant_id' => null,
            'actor_kind' => 'human',
            'acr' => 'aal2',
            'assurance_proof' => json_encode(sessionProof(7, 'aal1'), JSON_THROW_ON_ERROR),
            'weakest_satisfied_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $read = app(TokenAssuranceRecord::class)->read(new ResolvedToken(
            'sanctum',
            'drifted-token',
            SubjectKey::of(configuredUserProvider(), 7),
            true,
        ));

        self::assertSame(AssuranceReason::Sufficient, $read->reason);
        self::assertNotNull($read->evidence);
    }

    #[Test]
    public function evidence_read_under_a_capping_vocabulary_is_still_usable(): void
    {
        /*
         * Same rule, stated where a future implementer is most likely to add
         * the check: reading is vocabulary-independent. The record is usable
         * evidence regardless of what any vocabulary would call it now, and the
         * comparison is where the level decides anything.
         */
        app()->instance(AssuranceVocabulary::class, new CappingVocabulary());
        $session = $this->sessionRow('aal2', sessionProof(7, 'aal2'));

        $read = SessionEvidence::read($session);

        self::assertSame(AssuranceReason::Sufficient, $read->reason);
        self::assertSame(
            AssuranceOutcome::Sufficient,
            $this->comparator(new NistAssuranceVocabulary())
                ->compare($read, AssuranceRequirement::from('aal2'), $this->clock(), null)->outcome,
        );
    }
}
