<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

/**
 * Receives security-relevant events.
 *
 * Implementations ship in Phase 2.4 (activitylog, attest, null). Credential
 * material must never reach a sink — parent spec §7.6 requires a tested
 * redaction pass, which lives with the drivers.
 */
interface AuditSink
{
    /**
     * @param array<string, scalar|null> $context
     */
    public function record(string $event, array $context): void;
}
