<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Assurance;

use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;

/**
 * Names any satisfied credential aal2.
 *
 * Exists for one case InvertedVocabulary cannot serve. Self-service gates its
 * own operations at aal2 through the same comparator that now takes the bound
 * vocabulary, so a fixture that names the ACTING session's two-credential proof
 * aal1 refuses the operation before any projection is rewritten — the test would
 * be measuring the gate, not the writer.
 *
 * This keeps the acting session sufficient while still departing from
 * NistAssuranceVocabulary where it matters: after the removal one credential
 * remains, which Nist names aal1 and this names aal2. A writer that hard-coded
 * the shipped vocabulary stores the value this cannot produce.
 */
final class GenerousVocabulary implements AssuranceVocabulary
{
    public function name(AssuranceFacts $facts): string
    {
        return $facts->distinctCredentialCount === 0 ? 'aal0' : 'aal2';
    }
}
