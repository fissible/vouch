<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Assurance;

use DateTimeImmutable;
use Fissible\Vouch\Assurance\AssuranceEvidence;
use Fissible\Vouch\Assurance\AssuranceOutcome;
use Fissible\Vouch\Assurance\AssuranceRequirement;
use Fissible\Vouch\Assurance\EvidenceComparator;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Assurance\NistAssuranceVocabulary;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tests\Support\Assurance\CappingVocabulary;
use Fissible\Vouch\Tests\Support\Assurance\InvertedVocabulary;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\SubjectKey;
use PHPUnit\Framework\Attributes\Test;
use Psr\Clock\ClockInterface;

/**
 * Issue #10 — the vocabulary is supplied, never ambient.
 *
 * AssuranceEvidence::derivedAcr() resolved AssuranceVocabulary out of the
 * container, so a readonly value object's answer depended on global state at
 * the moment it was asked. These tests describe the replacement: evidence
 * exposes derived FACTS, and naming those facts is the caller's job with a
 * vocabulary it holds.
 */
final class VocabularyInjectionTest extends TestCase
{
    /** @param list<SatisfiedFactor> $factors */
    private function evidence(array $factors): AssuranceEvidence
    {
        return new AssuranceEvidence(SubjectKey::of('App\\Models\\User', 7), null, $factors);
    }

    private function factor(string $id, string $credentialId): SatisfiedFactor
    {
        return new SatisfiedFactor(
            factorId: $id,
            credentialId: $credentialId,
            kind: FactorKind::Knowledge,
            strength: FactorStrength::Knowledge,
            isMultiFactor: false,
            userVerified: false,
            phishingResistant: false,
            authenticatorId: null,
            satisfiedAt: new DateTimeImmutable('2026-09-01T10:00:00+00:00'),
        );
    }

    private function clock(): ClockInterface
    {
        return new class implements ClockInterface
        {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable('2026-09-01T10:00:01+00:00');
            }
        };
    }

    #[Test]
    public function it_exposes_derived_facts_rather_than_a_level_name(): void
    {
        $evidence = $this->evidence([$this->factor('password', 'cred-1')]);

        $facts = $evidence->facts();

        self::assertInstanceOf(AssuranceFacts::class, $facts);
        self::assertSame(1, $facts->distinctCredentialCount);
        self::assertFalse($facts->hasMultiFactorCredential);
    }

    #[Test]
    public function facts_do_not_change_when_the_bound_vocabulary_changes(): void
    {
        /*
         * The defect in one assertion. Under the old shape the same value
         * object returned different answers depending on what happened to be
         * bound; facts are derived from the factors alone and cannot.
         */
        $evidence = $this->evidence([
            $this->factor('password', 'cred-1'),
            $this->factor('totp', 'cred-2'),
        ]);

        app()->instance(\Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary::class, new NistAssuranceVocabulary());
        $first = $evidence->facts();

        app()->instance(\Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary::class, new CappingVocabulary());
        $second = $evidence->facts();

        self::assertEquals($first, $second);
        self::assertSame(2, $second->distinctCredentialCount);
    }

    #[Test]
    public function the_value_object_no_longer_offers_to_name_a_level(): void
    {
        /*
         * The deletion is the point of the issue, not an incidental detail of
         * the refactor. If derivedAcr() survives in any form, the ambient call
         * has somewhere to come back to.
         */
        self::assertFalse(
            method_exists(AssuranceEvidence::class, 'derivedAcr'),
            'AssuranceEvidence::derivedAcr() must be deleted, not merely bypassed.',
        );
    }

    #[Test]
    public function the_comparator_names_evidence_with_the_vocabulary_it_was_given(): void
    {
        /*
         * Two factors on two credentials: Nist names this aal2, the inverted
         * fixture names it aal1. Same evidence, same requirement, opposite
         * outcomes — which is only possible if the comparator asks the
         * vocabulary it holds.
         */
        $evidence = $this->evidence([
            $this->factor('password', 'cred-1'),
            $this->factor('totp', 'cred-2'),
        ]);
        $requirement = AssuranceRequirement::from('aal2');

        $generous = new EvidenceComparator(new NistAssuranceVocabulary());
        $strict = new EvidenceComparator(new InvertedVocabulary());

        self::assertSame(
            AssuranceOutcome::Sufficient,
            $generous->compare($evidence, $requirement, $this->clock(), null)->outcome,
        );
        self::assertSame(
            AssuranceOutcome::InsufficientLevel,
            $strict->compare($evidence, $requirement, $this->clock(), null)->outcome,
        );
    }

    #[Test]
    public function a_generous_vocabulary_grants_what_the_shipped_one_refuses(): void
    {
        /*
         * The opposite direction, and not redundant: a comparator that had been
         * broken into always refusing would pass the test above. One credential
         * is aal1 under Nist and aal2 under the inverted fixture.
         */
        $evidence = $this->evidence([$this->factor('password', 'cred-1')]);
        $requirement = AssuranceRequirement::from('aal2');

        self::assertSame(
            AssuranceOutcome::InsufficientLevel,
            (new EvidenceComparator(new NistAssuranceVocabulary()))
                ->compare($evidence, $requirement, $this->clock(), null)->outcome,
        );
        self::assertSame(
            AssuranceOutcome::Sufficient,
            (new EvidenceComparator(new InvertedVocabulary()))
                ->compare($evidence, $requirement, $this->clock(), null)->outcome,
        );
    }

    #[Test]
    public function the_comparator_still_orders_level_before_recency(): void
    {
        /*
         * Guards the injection change against silently reordering the refusal
         * contract: weak AND stale evidence must report the level problem, not
         * the age one, because they lead to different remediation.
         */
        $stale = new SatisfiedFactor(
            factorId: 'password',
            credentialId: 'cred-1',
            kind: FactorKind::Knowledge,
            strength: FactorStrength::Knowledge,
            isMultiFactor: false,
            userVerified: false,
            phishingResistant: false,
            authenticatorId: null,
            satisfiedAt: new DateTimeImmutable('2020-01-01T00:00:00+00:00'),
        );

        $comparison = (new EvidenceComparator(new NistAssuranceVocabulary()))->compare(
            $this->evidence([$stale]),
            AssuranceRequirement::from(['level' => 'aal2', 'max_age' => 'PT60S']),
            $this->clock(),
            null,
        );

        self::assertSame(AssuranceOutcome::InsufficientLevel, $comparison->outcome);
    }
}
