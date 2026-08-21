<?php

declare(strict_types=1);

namespace Fissible\Vouch\Jobs;

use Fissible\Vouch\Notifications\OtpOutboxDelivery;
use Fissible\Vouch\Notifications\OtpOutboxFailureReason;
use Fissible\Vouch\Notifications\RetryableOtpDeliveryFailure;
use Fissible\Vouch\Notifications\OtpQueueDispatcher;
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
        try {
            $delivery->deliver($this->outboxId);
        } catch (RetryableOtpDeliveryFailure) {
            $outbox = \Fissible\Vouch\Models\AuthChallengeOutbox::query()
                ->where('opaque_id', $this->outboxId)
                ->first();

            if ($outbox instanceof \Fissible\Vouch\Models\AuthChallengeOutbox) {
                app(OtpQueueDispatcher::class)->dispatchAfter($outbox, 1);
            }
        }
    }

    public function failed(?Throwable $exception): void
    {
        $outbox = \Fissible\Vouch\Models\AuthChallengeOutbox::query()
            ->where('opaque_id', $this->outboxId)
            ->first();

        app(OtpOutboxDelivery::class)->terminalize(
            $this->outboxId,
            $outbox?->provider_attempted_at !== null
                ? OtpOutboxFailureReason::ProviderExhausted
                : OtpOutboxFailureReason::WorkerFailure,
        );
    }
}
