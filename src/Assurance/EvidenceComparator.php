<?php

declare(strict_types=1);

namespace Fissible\Vouch\Assurance;

use Psr\Clock\ClockInterface;

final readonly class EvidenceComparator
{
    public function compare(AssuranceEvidence|EvidenceRead|null $candidate, AssuranceRequirement $requirement, ClockInterface $clock, ?string $tenantId): AssuranceComparison
    {
        if ($candidate instanceof EvidenceRead) {
            if (! $candidate->reason->outcome()->isSufficient()) {
                return new AssuranceComparison($candidate->reason->outcome(), $candidate->reason);
            }
            $candidate = $candidate->evidence;
        }
        if (! $candidate instanceof AssuranceEvidence) {
            return new AssuranceComparison(AssuranceOutcome::InvalidEvidence, AssuranceReason::NoEvidence);
        }
        if ($candidate->tenantId !== $tenantId) {
            return new AssuranceComparison(AssuranceOutcome::InvalidEvidence, AssuranceReason::TenantMismatch);
        }
        // Level precedes recency. Reversing them yields the wrong remediation
        // path for weak-and-stale evidence and changes the policy result.
        if (AssuranceLevelComparator::strength($candidate->derivedAcr()) < AssuranceLevelComparator::strength($requirement->level)) {
            return new AssuranceComparison(AssuranceOutcome::InsufficientLevel, AssuranceReason::LevelTooWeak);
        }
        $age = $requirement->maxAgeSeconds();
        if ($age !== null && $candidate->weakestSatisfiedAt()->getTimestamp() < $clock->now()->getTimestamp() - $age) {
            return new AssuranceComparison(AssuranceOutcome::InsufficientRecency, AssuranceReason::ProofTooOld);
        }
        return new AssuranceComparison(AssuranceOutcome::Sufficient, AssuranceReason::Sufficient);
    }
}
