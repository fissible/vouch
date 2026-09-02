<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Assurance;

use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Kernel\Assurance\ReportsReachableLevels;

/**
 * A vocabulary that states its own range, with the range and the naming rule
 * supplied separately so a test can make them AGREE or DISAGREE.
 *
 * The disagreement is the interesting fixture. A declaration is authoritative
 * right up until the probe holds a counter-example, and a host that ships one
 * has a defect worth being told about rather than papered over.
 */
final class DeclaringVocabulary implements AssuranceVocabulary, ReportsReachableLevels
{
    /**
     * @param  list<string>  $declared
     * @param  callable(AssuranceFacts): string  $rule
     */
    public function __construct(
        private readonly array $declared,
        private readonly mixed $rule,
    ) {}

    /** How many times the probe asked. A declaration must not stop it running. */
    public int $calls = 0;

    public function name(AssuranceFacts $facts): string
    {
        $this->calls++;

        return ($this->rule)($facts);
    }

    /** @return list<string> */
    public function reachableLevels(): array
    {
        return $this->declared;
    }
}
