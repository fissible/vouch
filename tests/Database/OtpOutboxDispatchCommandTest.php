<?php

declare(strict_types=1);

use Fissible\Vouch\Jobs\DeliverOtpChallenge;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthChallengeOutbox;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Notifications\OtpQueueDispatcher;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Contracts\Queue\Factory;
use Illuminate\Contracts\Queue\Queue as QueueContract;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Queue\SyncQueue;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Carbon;

uses(RefreshDatabase::class);

function dispatchableOutbox(bool $expired = false): AuthChallengeOutbox
{
    $attempt = AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'bound_context' => str_repeat('q', 64),
        'expires_at' => now()->addMinutes(10),
    ]);
    $challenge = AuthChallenge::create([
        'attempt_id' => $attempt->id,
        'factor_type' => 'password',
        'code_hash' => 'not-a-live-code',
        'expires_at' => $expired ? now()->subSecond() : now()->addMinute(),
    ]);

    return AuthChallengeOutbox::create([
        'opaque_id' => bin2hex(random_bytes(32)),
        'challenge_id' => $challenge->id,
        'payload' => ['target' => null, 'code' => 'redacted-test-value', 'decoy' => true],
        'status' => OtpOutboxStatus::Pending->value,
        'expires_at' => $expired ? now()->subSecond() : now()->addMinute(),
        'dispatched_at' => now()->subMinutes(2),
    ]);
}

it('redispatches stale live rows by database time and skips expired rows', function (): void {
    $live = dispatchableOutbox();
    dispatchableOutbox(expired: true);
    Queue::fake();

    // An application host can drift without changing the database authority.
    // With app-time comparisons this would classify the live row as expired
    // and silently strand the code in a queue-recovery path.
    Carbon::setTestNow(now()->addYear());

    try {
        $exit = Artisan::call('vouch:otp-outbox:dispatch');
        $output = Artisan::output();
    } finally {
        Carbon::setTestNow();
    }

    expect($exit)->toBe(0)
        ->and($output)->toContain('Dispatched 1 pending OTP outbox row(s).');

    Queue::assertPushedTimes(DeliverOtpChallenge::class, 1);
    Queue::assertPushed(DeliverOtpChallenge::class, fn (DeliverOtpChallenge $job): bool =>
        $job->outboxId === $live->opaque_id);
});

it('redispatches exactly at the stale deadline but not one second before it', function (): void {
    $stale = dispatchableOutbox();
    $fresh = dispatchableOutbox();
    $time = app(DatabaseTime::class);

    DB::update(
        'UPDATE auth_challenge_outbox SET dispatched_at = '
        . $time->deadlineSqlHere()
        . ' WHERE id = ?',
        [-60, $stale->id],
    );
    DB::update(
        'UPDATE auth_challenge_outbox SET dispatched_at = '
        . $time->deadlineSqlHere()
        . ' WHERE id = ?',
        [-59, $fresh->id],
    );
    Queue::fake();

    expect(Artisan::call('vouch:otp-outbox:dispatch'))->toBe(0)
        ->and(Artisan::output())->toContain('Dispatched 1 pending OTP outbox row(s).');

    Queue::assertPushed(DeliverOtpChallenge::class, fn (DeliverOtpChallenge $job): bool =>
        $job->outboxId === $stale->opaque_id);
    Queue::assertNotPushed(DeliverOtpChallenge::class, fn (DeliverOtpChallenge $job): bool =>
        $job->outboxId === $fresh->opaque_id);
});

it('rejects a synchronous queue even when there is no pending work', function (): void {
    $queues = new class implements Factory
    {
        public function connection($name = null): QueueContract
        {
            return new SyncQueue();
        }
    };
    app()->instance(OtpQueueDispatcher::class, new OtpQueueDispatcher(
        $queues,
        app(DatabaseTime::class),
        'inline',
        'vouch-otp',
    ));

    expect(fn (): int => Artisan::call('vouch:otp-outbox:dispatch'))
        ->toThrow(InvalidArgumentException::class, 'durable asynchronous queue');
});
