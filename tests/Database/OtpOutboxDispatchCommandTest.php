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

it('redispatches a row at the stale deadline and leaves a fresher one alone', function (): void {
    /*
     * The stale row sits EXACTLY at the deadline, which is the assertion that
     * distinguishes `<=` from `<`. That direction is safe against a slow
     * runner: elapsed time only makes a row staler, never fresher.
     *
     * The fresh row deliberately sits well inside the window rather than one
     * second inside it. The one-second form was a real race, not a theoretical
     * one — the eligibility predicate compares against the DATABASE clock at
     * query time, so a row stamped at "now minus 59 seconds" becomes eligible
     * the moment a second of wall clock passes between the UPDATE and the
     * command. It failed on CI under the mutation job's coverage
     * instrumentation, and reproduces locally with a 1.1s delay injected
     * before the dispatch call.
     *
     * There is no seam to pin: DatabaseTime evaluates CURRENT_TIMESTAMP in the
     * database precisely so no application clock can be substituted. The exact
     * deadline constant is therefore pinned by the test below this one, which
     * needs no clock at all.
     */
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
        [-30, $fresh->id],
    );
    Queue::fake();

    expect(Artisan::call('vouch:otp-outbox:dispatch'))->toBe(0)
        ->and(Artisan::output())->toContain('Dispatched 1 pending OTP outbox row(s).');

    Queue::assertPushed(DeliverOtpChallenge::class, fn (DeliverOtpChallenge $job): bool =>
        $job->outboxId === $stale->opaque_id);
    Queue::assertNotPushed(DeliverOtpChallenge::class, fn (DeliverOtpChallenge $job): bool =>
        $job->outboxId === $fresh->opaque_id);
});

it('measures the redispatch deadline as exactly sixty seconds', function (): void {
    /*
     * The half of the boundary a wall clock cannot assert deterministically.
     * The test above proves the comparison is inclusive and that fresher rows
     * are left alone; this proves the window is 60 seconds and not 59 or 30,
     * which is what the removed one-second row used to catch.
     *
     * Asserted on the bound parameter rather than by timing, because the
     * binding is the constant. A behavioural form would have to observe the
     * database within one second of stamping a row, which no loaded runner can
     * be held to.
     */
    dispatchableOutbox();
    Queue::fake();
    DB::enableQueryLog();

    Artisan::call('vouch:otp-outbox:dispatch');

    $deadlines = [];
    foreach (DB::getRawQueryLog() as $entry) {
        // The eligibility predicate only; the command's own dispatched_at
        // write also names the column and carries no deadline.
        if (str_contains((string) $entry['raw_query'], 'dispatched_at <=')) {
            $deadlines[] = $entry['raw_query'];
        }
    }
    DB::disableQueryLog();

    /*
     * Every engine renders the bound interval differently -- SQLite
     * printf('%+d seconds', -60), MySQL INTERVAL -60 SECOND, PostgreSQL
     * (-60 * INTERVAL '1 second') -- and all three carry the literal -60.
     */
    expect($deadlines)->not->toBeEmpty();
    foreach ($deadlines as $query) {
        expect($query)->toContain('-60');
    }
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
