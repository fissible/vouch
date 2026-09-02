<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Assurance;

use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;

/**
 * A host vocabulary that CAN emit aal3.
 *
 * Stands in for the deployment the README's escape hatch describes: one that
 * captures hardware-binding evidence -- WebAuthn backup-eligibility and
 * backup-state flags, or attestation -- and is therefore entitled to name a
 * level `NistAssuranceVocabulary` refuses to.
 *
 * The rule here is deliberately naive, because what is under test is that the
 * SEAM carries a level the shipped vocabulary cannot produce, not how a real
 * host would decide it. A faithful hardware-binding rule would need facts
 * AssuranceFacts does not carry, which is the whole reason the shipped
 * vocabulary caps where it does.
 */
final class Aal3CapableVocabulary implements AssuranceVocabulary
{
    public function name(AssuranceFacts $facts): string
    {
        if ($facts->distinctCredentialCount === 0) {
            return 'aal0';
        }

        return $facts->distinctCredentialCount >= 2 ? 'aal3' : 'aal1';
    }
}
