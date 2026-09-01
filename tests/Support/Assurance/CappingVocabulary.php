<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Assurance;

use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;

/**
 * A host vocabulary that caps at aal1.
 *
 * This is the migration case the contract is written for: an operator decides
 * their old naming was too generous and binds something stricter. Every
 * historical row now disagrees with a fresh derivation, and the disagreement
 * must be visible without rewriting history or refusing valid evidence.
 */
final class CappingVocabulary implements AssuranceVocabulary
{
    public function name(AssuranceFacts $facts): string
    {
        return $facts->distinctCredentialCount === 0 ? 'aal0' : 'aal1';
    }
}
