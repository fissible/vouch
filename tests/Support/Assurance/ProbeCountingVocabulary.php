<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Assurance;

use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;

/**
 * Counts how many times the probe asked it to name something.
 *
 * The probe runs HOST code. Boundedness is therefore not a performance
 * preference but a contract: a diagnostic that called an unknown implementation
 * an unbounded number of times would be a denial of service a host inflicted on
 * itself by running `vouch:assurance-map`.
 */
final class ProbeCountingVocabulary implements AssuranceVocabulary
{
    public int $calls = 0;

    /** @var list<string> */
    public array $emitted = [];

    public function name(AssuranceFacts $facts): string
    {
        $this->calls++;

        $level = $facts->distinctCredentialCount === 0 ? 'aal0'
            : ($facts->distinctCredentialCount >= 2 ? 'aal2' : 'aal1');

        $this->emitted[] = $level;

        return $level;
    }
}
