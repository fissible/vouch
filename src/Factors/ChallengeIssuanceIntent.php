<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

/**
 * Target-free issuance input, constructed before identifier resolution.
 *
 * No resolved user, credential, identifier row, or delivery address can be
 * represented here. That makes charging a nonexistent identifier differently
 * from a real one structurally difficult rather than conventionally forbidden.
 */
final readonly class ChallengeIssuanceIntent
{
    public function __construct(
        public int $attemptId,
        public string $submittedIdentifier,
        public string $factorId,
        public string $action,
        public ?string $tenantId,
        public ?string $clientIp,
        public ?string $clientUserAgent,
    ) {}
}
