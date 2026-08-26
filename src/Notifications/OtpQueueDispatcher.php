<?php

declare(strict_types=1);

namespace Fissible\Vouch\Notifications;

use Fissible\Vouch\Jobs\DeliverOtpChallenge;
use Fissible\Vouch\Jobs\DeliverIdentifierVerification;
use Fissible\Vouch\Models\AuthChallengeOutbox;
use Fissible\Vouch\Models\AuthIdentifierVerificationOutbox;
use Fissible\Vouch\Models\AuthRecoveryProofOutbox;
use Fissible\Vouch\Jobs\DeliverRecoveryProof;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Contracts\Queue\Factory;
use Illuminate\Contracts\Queue\Queue;
use Illuminate\Queue\FailoverQueue;
use Illuminate\Queue\NullQueue;
use Illuminate\Queue\SyncQueue;
use InvalidArgumentException;

/** Pushes only opaque outbox identifiers onto a durable, asynchronous queue. */
final readonly class OtpQueueDispatcher
{
    public function __construct(
        private Factory $queues,
        private DatabaseTime $time,
        private ?string $connection,
        private string $queue,
    ) {}

    public function assertAsynchronous(): void
    {
        $resolved = $this->connection();

        if ($resolved instanceof SyncQueue || $resolved instanceof NullQueue) {
            throw new InvalidArgumentException(sprintf(
                'Vouch OTP delivery requires a durable asynchronous queue; connection "%s" resolved to %s. Configure a database, Redis, SQS, or another durable worker-backed connection before enabling email or SMS OTP.',
                $this->connection ?? 'default',
                $resolved::class,
            ));
        }

        if ($resolved instanceof FailoverQueue) {
            foreach ($resolved->connections as $connection) {
                $candidate = $resolved->manager->connection($connection);

                if ($candidate instanceof SyncQueue || $candidate instanceof NullQueue) {
                    throw new InvalidArgumentException(sprintf(
                        'Vouch OTP delivery requires every failover queue to be durable and asynchronous; connection "%s" contains %s.',
                        $this->connection ?? 'default',
                        $candidate::class,
                    ));
                }
            }
        }
    }

    public function dispatch(AuthChallengeOutbox $outbox): void
    {
        $this->assertAsynchronous();

        $this->connection()->push(
            new DeliverOtpChallenge($outbox->opaque_id),
            queue: $this->queue,
        );

        AuthChallengeOutbox::query()
            ->whereKey($outbox->id)
            ->where('status', OtpOutboxStatus::Pending->value)
            ->whereNull('dispatched_at')
            ->update([
                'dispatched_at' => $this->time->now(),
            ]);
    }

    public function dispatchVerification(AuthIdentifierVerificationOutbox $outbox): void
    {
        $this->assertAsynchronous();
        $this->connection()->push(new DeliverIdentifierVerification($outbox->opaque_id), queue: $this->queue);

        AuthIdentifierVerificationOutbox::query()->whereKey($outbox->id)
            ->where('status', OtpOutboxStatus::Pending->value)->whereNull('dispatched_at')
            ->update(['dispatched_at' => $this->time->now()]);
    }

    public function dispatchRecoveryProof(AuthRecoveryProofOutbox $outbox): void
    {
        $this->assertAsynchronous();
        $this->connection()->push(new DeliverRecoveryProof($outbox->opaque_id), queue: $this->queue);
        AuthRecoveryProofOutbox::query()->whereKey($outbox->id)
            ->where('status', OtpOutboxStatus::Pending->value)->whereNull('dispatched_at')
            ->update(['dispatched_at' => $this->time->now()]);
    }

    public function dispatchAfter(AuthChallengeOutbox $outbox, int $delaySeconds): void
    {
        if ($delaySeconds < 1) {
            throw new \InvalidArgumentException('A delayed OTP dispatch requires a positive delay.');
        }

        $this->assertAsynchronous();

        $this->connection()->later(
            $delaySeconds,
            new DeliverOtpChallenge($outbox->opaque_id),
            queue: $this->queue,
        );
    }

    private function connection(): Queue
    {
        return $this->queues->connection($this->connection);
    }
}
