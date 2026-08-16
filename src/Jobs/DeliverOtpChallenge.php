<?php

declare(strict_types=1);

namespace Fissible\Vouch\Jobs;

use Fissible\Vouch\Notifications\OtpOutboxDelivery;
use Illuminate\Contracts\Queue\ShouldQueue;
use Throwable;

/** Queue payload contains only an opaque outbox locator, never target or code. */
final class DeliverOtpChallenge implements ShouldQueue
{
    public int $tries = 5;

    public function __construct(public readonly string $outboxId)
    {
    }

    public function handle(OtpOutboxDelivery $delivery): void
    {
        $delivery->deliver($this->outboxId);
    }

    public function failed(?Throwable $exception): void
    {
        app(OtpOutboxDelivery::class)->terminalize($this->outboxId);
    }
}
