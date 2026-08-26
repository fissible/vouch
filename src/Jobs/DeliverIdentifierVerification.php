<?php

declare(strict_types=1);

namespace Fissible\Vouch\Jobs;

use Fissible\Vouch\Verification\VerificationOutboxDelivery;
use Illuminate\Contracts\Queue\ShouldQueue;

/** Queue payload contains only the identifier-verification outbox locator. */
final class DeliverIdentifierVerification implements ShouldQueue
{
    public int $tries = 5;

    public function __construct(public readonly string $outboxId) {}

    public function handle(VerificationOutboxDelivery $delivery): void
    {
        $delivery->execute($this->outboxId);
    }
}
