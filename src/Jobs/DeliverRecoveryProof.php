<?php

declare(strict_types=1);

namespace Fissible\Vouch\Jobs;

use Fissible\Vouch\Recovery\RecoveryProofOutboxDelivery;
use Illuminate\Contracts\Queue\ShouldQueue;

final class DeliverRecoveryProof implements ShouldQueue
{
    public int $tries = 5;
    public function __construct(public readonly string $outboxId) {}
    public function handle(RecoveryProofOutboxDelivery $delivery): void { $delivery->execute($this->outboxId); }
}
