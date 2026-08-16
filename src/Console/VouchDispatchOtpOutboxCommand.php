<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

use Fissible\Vouch\Models\AuthChallengeOutbox;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Notifications\OtpQueueDispatcher;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Console\Command;

/** Recovers the durable-row-before-queue-push crash window. */
final class VouchDispatchOtpOutboxCommand extends Command
{
    protected $signature = 'vouch:otp-outbox:dispatch';

    protected $description = 'Redispatch live pending Vouch OTP outbox rows';

    public function handle(OtpQueueDispatcher $dispatcher, DatabaseTime $time): int
    {
        $dispatcher->assertAsynchronous();
        $count = 0;

        AuthChallengeOutbox::query()
            ->where('status', OtpOutboxStatus::Pending->value)
            ->where('expires_at', '>', $time->now())
            ->where(static function ($query) use ($time): void {
                $query->whereNull('dispatched_at')
                    ->orWhereRaw($time->dispatchedAtAtOrBeforeDeadlineSql(), [-60]);
            })
            ->orderBy('id')
            ->chunkById(100, function ($outboxes) use ($dispatcher, &$count): void {
                foreach ($outboxes as $outbox) {
                    $dispatcher->dispatch($outbox);
                    $count++;
                }
            });

        $this->components->info(sprintf('Dispatched %d pending OTP outbox row(s).', $count));

        return self::SUCCESS;
    }
}
