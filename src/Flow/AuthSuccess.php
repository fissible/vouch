<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;

/**
 * What a completed authentication established.
 *
 * Deliberately carries no HTTP or session object. SessionLifecycle receives
 * this and performs the rotation; the flow that produced it never touches a
 * session, which is what keeps the two testable apart.
 */
final readonly class AuthSuccess
{
    /**
     * @param  list<SatisfiedFactor>  $factors  Fresh evidence from THIS attempt.
     */
    public function __construct(
        public int $userId,
        public array $factors,
        public AssuranceFacts $facts,
        public string $acr,
        public string $boundContext,
    ) {}

    /**
     * The authentication methods, in the order they were satisfied.
     *
     * @return list<string>
     */
    public function amr(): array
    {
        // No array_values(): array_map over a list already yields a list, and
        // PHPStan flags the redundant call rather than letting it sit as cargo.
        return array_map(
            static fn (SatisfiedFactor $factor): string => $factor->factorId,
            $this->factors,
        );
    }
}
