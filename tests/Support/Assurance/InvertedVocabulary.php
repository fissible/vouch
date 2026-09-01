<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Assurance;

use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;

/**
 * Names the same facts the OPPOSITE way to NistAssuranceVocabulary.
 *
 * Deliberately not a distinctive vocabulary of its own invented strings:
 * AssuranceLevelComparator::strength() throws on any name outside the aal
 * ladder, so a fixture emitting 'vouch-high' would prove nothing except that
 * the comparator rejects it.
 *
 * Inverting inside the known ladder is what makes routing falsifiable. A writer
 * that quietly constructed its own NistAssuranceVocabulary — satisfying "does
 * not touch the container" while ignoring the host's choice entirely — stores
 * the Nist answer, which is exactly the value this vocabulary does not produce.
 */
final class InvertedVocabulary implements AssuranceVocabulary
{
    public function name(AssuranceFacts $facts): string
    {
        if ($facts->distinctCredentialCount === 0) {
            return 'aal0';
        }

        return $facts->distinctCredentialCount >= 2 || $facts->hasMultiFactorCredential
            ? 'aal1'
            : 'aal2';
    }
}
