<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

use Fissible\Vouch\Models\AuthIdentifierVerification;
use Fissible\Vouch\Models\AuthRecoveryProof;
use Illuminate\Database\Connection;

final readonly class ProofAttemptStore
{
    public function __construct(
        private Connection $connection,
        private ThrottleConfiguration $configuration,
    ) {}

    public function recordFailure(AuthRecoveryProof|AuthIdentifierVerification $proof): void
    {
        $grammar = $this->connection->getQueryGrammar();
        $table = $grammar->wrapTable($proof->getTable());
        $id = $grammar->wrap('id');
        $attempts = $grammar->wrap('attempts');
        $burnedAt = $grammar->wrap('burned_at');
        $consumedAt = $grammar->wrap('consumed_at');
        $supersededAt = $grammar->wrap('superseded_at');
        $expiresAt = $grammar->wrap('expires_at');
        $updatedAt = $grammar->wrap('updated_at');
        $limit = $this->configuration->challengeAttempts;

        /*
         * The selected row owns the budget: spelling, tenant, IP and submitted
         * code cannot give the same proof another set of guesses. Increment and
         * burn must share one UPDATE; PHP read-increment-write collapses
         * concurrent failures, and separate writes expose a live exhausted row.
         */
        $this->connection->update(
            "UPDATE {$table} SET "
            . "{$burnedAt} = CASE WHEN {$attempts} + 1 >= ? "
            . "THEN CURRENT_TIMESTAMP ELSE {$burnedAt} END, "
            // MySQL evaluates assignments left-to-right. Test the OLD count
            // before incrementing, or MySQL burns one attempt too soon.
            . "{$attempts} = {$attempts} + 1, "
            . "{$updatedAt} = CURRENT_TIMESTAMP "
            . "WHERE {$id} = ? AND {$burnedAt} IS NULL "
            . "AND {$consumedAt} IS NULL AND {$supersededAt} IS NULL "
            . "AND {$expiresAt} > CURRENT_TIMESTAMP AND {$attempts} < ?",
            [$limit, $proof->id, $limit],
        );
    }
}
