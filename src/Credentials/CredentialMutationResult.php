<?php

declare(strict_types=1);

namespace Fissible\Vouch\Credentials;

final class CredentialMutationResult
{
    /** @param list<CredentialDriverFailure> $driverFailures */
    public function __construct(
        public int $revoked = 0,
        public array $driverFailures = [],
        public bool $driverRevocationsComplete = false,
    ) {}

    /**
     * At top level this runs before CredentialMutation returns. If the
     * mutation joined a caller transaction, it runs on that transaction's
     * outermost commit and updates the same result afterwards.
     */
    public function recordDriverFailure(CredentialDriverFailure $failure): void
    {
        $this->driverFailures[] = $failure;
    }

    /** Mark the returned result final after all deferred driver calls ran. */
    public function markDriverRevocationsComplete(): void
    {
        $this->driverRevocationsComplete = true;
    }
}
