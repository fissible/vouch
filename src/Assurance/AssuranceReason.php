<?php

declare(strict_types=1);

namespace Fissible\Vouch\Assurance;

enum AssuranceReason
{
    case Sufficient;
    case LevelTooWeak;
    case ProofTooOld;
    case NoEvidence;
    case LegacyNoProof;
    case ProofMalformed;
    case SessionRevoked;
    case RecoveryGrace;
    case SubjectMismatch;
    case TenantMismatch;

    public function outcome(): AssuranceOutcome
    {
        return match ($this) {
            self::Sufficient => AssuranceOutcome::Sufficient,
            self::LevelTooWeak => AssuranceOutcome::InsufficientLevel,
            self::ProofTooOld => AssuranceOutcome::InsufficientRecency,
            default => AssuranceOutcome::InvalidEvidence,
        };
    }
}
