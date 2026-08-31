<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

/** Exact committed deletion counts from one vouch maintenance snapshot. */
final readonly class PruneResult
{
    public function __construct(
        public int $attempts,
        public int $challenges,
        public int $revokedSessions,
        public int $throttleCounters,
        public int $expiredLocks,
        public int $tupleMarkers,
        public int $deliveredOutbox,
        public int $undeliveredOutbox,
        public int $deliveryReservations,
        public int $reclaimedTokenAssurances,
        public int $retainedTokenAssurances,
        public int $unsupportedTokenAssurances,
        public int $erroredTokenAssurances,
        /** @var list<string> */
        public array $tokenAssuranceSweepErrors,
        /** @var list<string> */
        public array $unsupportedTokenAssuranceIssuers,
    ) {}

    public function foundUndeliveredWork(): bool
    {
        return $this->undeliveredOutbox > 0;
    }
}
