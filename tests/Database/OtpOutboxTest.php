<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Jobs\DeliverOtpChallenge;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthChallengeOutbox;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Notifications\OtpChallengeOutbox;
use Fissible\Vouch\Notifications\OtpOutboxDelivery;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Notifications\OtpQueueDispatcher;
use Fissible\Vouch\Notifications\PermanentOtpDeliveryFailure;
use Fissible\Vouch\Notifications\TransientOtpDeliveryFailure;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Throttle\IssuancePermission;
use Fissible\Vouch\Throttle\ThrottleKey;
use Illuminate\Contracts\Queue\Factory;
use Illuminate\Contracts\Queue\Queue as QueueContract;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Queue\Connectors\DatabaseConnector;
use Illuminate\Queue\Connectors\NullConnector;
use Illuminate\Queue\Connectors\SyncConnector;
use Illuminate\Queue\FailoverQueue;
use Illuminate\Queue\NullQueue;
use Illuminate\Queue\QueueManager;
use Illuminate\Queue\SyncQueue;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Psr\Clock\ClockInterface;

uses(RefreshDatabase::class);

final class RetryingOtpDelivery implements OtpDelivery
{
    /** @var list<string> */
    public array $codes = [];

    public function __construct(private int $failures = 1)
    {
    }

    public function deliver(AuthIdentifier $identifier, string $code, DateTimeImmutable $expiresAt): void
    {
        $this->codes[] = $code;

        if ($this->failures > 0) {
            $this->failures--;
            throw new RuntimeException(sprintf(
                'provider failed for %s while sending %s',
                $identifier->value,
                $code,
            ));
        }
    }
}

final class PermanentlyFailingOtpDelivery implements OtpDelivery
{
    public function deliver(AuthIdentifier $identifier, string $code, DateTimeImmutable $expiresAt): void
    {
        throw new PermanentOtpDeliveryFailure('provider rejected destination');
    }
}

final class ExpiringThenFailingOtpDelivery implements OtpDelivery
{
    public function deliver(AuthIdentifier $identifier, string $code, DateTimeImmutable $expiresAt): void
    {
        DB::table('auth_challenge_outbox')->update([
            'expires_at' => now()->subSecond(),
        ]);

        throw new RuntimeException('provider failed after the database deadline');
    }
}

/** @return array{EmailOtpFactor, AuthAttempt, ArrayOtpDelivery} */
function outboxFixture(): array
{
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->forgetInstance(EmailOtpFactor::class);
    $factor = app(EmailOtpFactor::class);
    $identifier = AuthIdentifier::create([
        'user_id' => 7,
        'type' => 'email',
        'value' => 'outbox@acme.example',
        'verified_at' => now(),
    ]);
    $factor->enroll(7, ['identifier_id' => $identifier->id]);
    $attempt = AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'user_id' => 7,
        'identifier' => $identifier->value,
        'bound_context' => str_repeat('o', 64),
        'expires_at' => now()->addMinutes(10),
    ]);

    return [$factor, $attempt, $delivery];
}

/** @return array{target: array{id: int, user_id: int, type: string, value: string, verified_at: string}|null, code: string, decoy: bool} */
function requiredOutboxPayload(AuthChallengeOutbox $outbox): array
{
    $payload = $outbox->payload;

    if ($payload === null) {
        throw new RuntimeException('Expected a live encrypted OTP outbox payload.');
    }

    return $payload;
}

function requiredRawOutboxPayload(): string
{
    $payload = DB::table('auth_challenge_outbox')->value('payload');

    if (! is_string($payload)) {
        throw new RuntimeException('Expected a raw encrypted OTP outbox payload.');
    }

    return $payload;
}

function queueFactoryFor(QueueContract $queue): Factory
{
    return new class($queue) implements Factory
    {
        public function __construct(private QueueContract $queue)
        {
        }

        public function connection($name = null): QueueContract
        {
            return $this->queue;
        }
    };
}

it('commits a verifiable challenge and encrypted outbox without delivering inline', function (): void {
    [$factor, $attempt, $delivery] = outboxFixture();

    $challenge = $factor->challenge(new ChallengeRequest($attempt));
    $outbox = AuthChallengeOutbox::query()->firstOrFail();
    $identifier = AuthIdentifier::query()->sole();
    $payload = requiredOutboxPayload($outbox);
    $rawPayload = requiredRawOutboxPayload();
    $verifiedAt = $identifier->verified_at?->toISOString();

    expect($verifiedAt)->toBeString()
        ->and($challenge)->toBeInstanceOf(AuthChallenge::class)
        ->and($delivery->sent)->toBe([])
        ->and($outbox->opaque_id)->toHaveLength(64)
        ->and($outbox->opaque_id)->toMatch('/^[a-f0-9]{64}$/')
        ->and($outbox->dispatched_at)->not->toBeNull()
        ->and($outbox->expires_at->getTimestamp())->toBe($challenge?->expires_at->getTimestamp())
        ->and($payload['code'])->toBeString()->toHaveLength(6)
        ->and($payload['target'])->toBe([
            'id' => $identifier->id,
            'user_id' => 7,
            'type' => 'email',
            'value' => 'outbox@acme.example',
            'verified_at' => $verifiedAt,
        ]);

    expect($rawPayload)->not->toContain($payload['code'])
        ->and($rawPayload)->not->toContain('outbox@acme.example');
    expect($outbox->toArray())->not->toHaveKey('payload');
    expect(json_encode($outbox))->not->toContain($payload['code']);
    expect(serialize(new DeliverOtpChallenge($outbox->opaque_id)))
        ->not->toContain($payload['code'])
        ->and(serialize(new DeliverOtpChallenge($outbox->opaque_id)))
        ->not->toContain('outbox@acme.example');

    Queue::assertPushed(DeliverOtpChallenge::class, fn (DeliverOtpChallenge $job): bool =>
        $job->outboxId === $outbox->opaque_id);
});

it('issues a first decoy resend when there is no pending challenge to reuse', function (): void {
    [$factor, $attempt] = outboxFixture();

    $challenge = $factor->challenge(new ChallengeRequest(
        attempt: $attempt,
        decoy: true,
        reusePending: true,
    ));

    expect($challenge)->toBeInstanceOf(AuthChallenge::class)
        ->and($challenge?->is_decoy)->toBeTrue()
        ->and($challenge?->credential_id)->toBeNull()
        ->and(AuthChallengeOutbox::query()->count())->toBe(1);
});

it('never verifies a decoy challenge even with its generated code', function (): void {
    [$factor, $attempt] = outboxFixture();
    $challenge = $factor->challenge(new ChallengeRequest(
        attempt: $attempt,
        decoy: true,
    ));

    if (! $challenge instanceof AuthChallenge) {
        throw new RuntimeException('Expected a decoy challenge.');
    }

    $code = requiredOutboxPayload(AuthChallengeOutbox::query()->sole())['code'];
    $result = $factor->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $code],
        challenge: $challenge,
    ));

    expect($result->failure)->toBe(FactorFailure::NoCredential)
        ->and($result->isSatisfied())->toBeFalse()
        ->and($challenge->refresh()->attempts)->toBe(0);
});

it('fails closed when a supplied challenge vanished after the caller loaded it', function (): void {
    [$factor, $attempt] = outboxFixture();
    $challenge = $factor->challenge(new ChallengeRequest($attempt));

    if (! $challenge instanceof AuthChallenge) {
        throw new RuntimeException('Expected a real challenge.');
    }

    $code = requiredOutboxPayload(AuthChallengeOutbox::query()->sole())['code'];
    $challenge->delete();

    expect($factor->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $code],
        challenge: $challenge,
    ))->failure)->toBe(FactorFailure::NoCredential);
});

it('fails closed when the attempt vanishes before challenge issuance', function (): void {
    [$factor, $attempt] = outboxFixture();
    $attempt->delete();

    expect(fn () => $factor->challenge(new ChallengeRequest($attempt)))
        ->toThrow(RuntimeException::class, 'attempt vanished')
        ->and(AuthChallenge::query()->count())->toBe(0)
        ->and(AuthChallengeOutbox::query()->count())->toBe(0);
});

it('refuses an identifier that lost verification before issuance', function (): void {
    [$factor, $attempt] = outboxFixture();
    DB::table('auth_identifiers')->update(['verified_at' => null]);

    expect(fn () => $factor->challenge(new ChallengeRequest($attempt)))
        ->toThrow(InvalidArgumentException::class, 'is not verified')
        ->and(AuthChallenge::query()->count())->toBe(0)
        ->and(AuthChallengeOutbox::query()->count())->toBe(0);
});

it('delivers the stored code once and immediately redacts the terminal row', function (): void {
    [$factor, $attempt, $delivery] = outboxFixture();
    $challenge = $factor->challenge(new ChallengeRequest($attempt));
    $outbox = AuthChallengeOutbox::query()->firstOrFail();
    $code = requiredOutboxPayload($outbox)['code'];
    $before = now()->subDay();
    DB::table('auth_challenge_outbox')->where('id', $outbox->id)->update([
        'updated_at' => $before,
    ]);

    $job = new DeliverOtpChallenge($outbox->opaque_id);

    expect($job->tries)->toBe(5);

    $job->handle(app(OtpOutboxDelivery::class));

    $terminal = $outbox->refresh();

    expect($delivery->lastCode())->toBe($code)
        ->and(password_verify($code, (string) $challenge?->code_hash))->toBeTrue()
        ->and($terminal->status)->toBe(OtpOutboxStatus::Delivered->value)
        ->and($terminal->payload)->toBeNull()
        ->and($terminal->delivered_at)->not->toBeNull()
        ->and($terminal->updated_at->greaterThan($before))->toBeTrue();
});

it('terminalizes a non-decoy payload whose immutable target is absent', function (): void {
    [$factor, $attempt, $delivery] = outboxFixture();
    $factor->challenge(new ChallengeRequest($attempt));
    $outbox = AuthChallengeOutbox::query()->firstOrFail();
    $payload = requiredOutboxPayload($outbox);
    $outbox->update(['payload' => [
        'target' => null,
        'code' => $payload['code'],
        'decoy' => false,
    ]]);

    app(OtpOutboxDelivery::class)->deliver($outbox->opaque_id);

    expect($outbox->refresh()->status)->toBe(OtpOutboxStatus::Undeliverable->value)
        ->and($outbox->payload)->toBeNull()
        ->and($outbox->undeliverable_at)->not->toBeNull()
        ->and($delivery->sent)->toBe([]);
});

it('retries the exact stored code without extending expiry or charging issuance again', function (): void {
    [$factor, $attempt] = outboxFixture();
    expect(app(Fissible\Vouch\Contracts\AuthThrottleStore::class)->permitIssuance(
        app(ThrottleKey::class)->issuance('outbox@acme.example', null),
    ))->toBe(IssuancePermission::Permitted);

    $challenge = $factor->challenge(new ChallengeRequest($attempt));
    $outbox = AuthChallengeOutbox::query()->firstOrFail();
    $payload = requiredOutboxPayload($outbox);
    $expiry = $outbox->expires_at->getTimestamp();
    $transport = new RetryingOtpDelivery();
    app()->instance(OtpDelivery::class, $transport);

    $failure = null;

    try {
        app(OtpOutboxDelivery::class)->deliver($outbox->opaque_id);
    } catch (TransientOtpDeliveryFailure $exception) {
        $failure = $exception;
    }

    expect($failure)->toBeInstanceOf(TransientOtpDeliveryFailure::class);

    if (! $failure instanceof TransientOtpDeliveryFailure) {
        throw new RuntimeException('Expected a redacted transient failure.');
    }

    expect((string) $failure)->not->toContain($payload['code'])
        ->and((string) $failure)->not->toContain('outbox@acme.example');

    $failedJobRecord = (string) json_encode([
        'payload' => serialize(new DeliverOtpChallenge($outbox->opaque_id)),
        'exception' => (string) $failure,
    ]);
    $representativeLog = sprintf(
        '%s: %s',
        $failure::class,
        $failure->getMessage(),
    );

    expect($failedJobRecord)->not->toContain($payload['code'])
        ->and($failedJobRecord)->not->toContain('outbox@acme.example')
        ->and($representativeLog)->not->toContain($payload['code'])
        ->and($representativeLog)->not->toContain('outbox@acme.example');

    $pending = $outbox->refresh();

    expect($pending->status)->toBe(OtpOutboxStatus::Pending->value)
        ->and($pending->payload)->not->toBeNull()
        ->and($pending->expires_at->getTimestamp())->toBe($expiry);

    app(OtpOutboxDelivery::class)->deliver($outbox->opaque_id);

    expect($transport->codes)->toBe([$payload['code'], $payload['code']])
        ->and(password_verify($payload['code'], (string) $challenge?->code_hash))->toBeTrue()
        ->and($outbox->refresh()->payload)->toBeNull()
        ->and(DB::table('auth_throttle_counters')->where('dimension', 'issuance')->value('count'))->toBe(1);
});

it('redacts permanent and exhausted failures without retrying a dead credential', function (): void {
    [$factor, $attempt] = outboxFixture();
    $factor->challenge(new ChallengeRequest($attempt));
    $outbox = AuthChallengeOutbox::query()->firstOrFail();
    $before = now()->subDay();
    DB::table('auth_challenge_outbox')->where('id', $outbox->id)->update([
        'updated_at' => $before,
    ]);
    app()->instance(OtpDelivery::class, new PermanentlyFailingOtpDelivery());

    app(OtpOutboxDelivery::class)->deliver($outbox->opaque_id);

    expect($outbox->refresh()->status)->toBe(OtpOutboxStatus::Undeliverable->value)
        ->and($outbox->payload)->toBeNull()
        ->and($outbox->undeliverable_at)->not->toBeNull()
        ->and($outbox->updated_at->greaterThan($before))->toBeTrue();

    $factor->challenge(new ChallengeRequest($attempt));
    $exhausted = AuthChallengeOutbox::query()->where('status', 'pending')->firstOrFail();
    (new DeliverOtpChallenge($exhausted->opaque_id))->failed(new RuntimeException('tries exhausted'));

    expect($exhausted->refresh()->status)->toBe(OtpOutboxStatus::Undeliverable->value)
        ->and($exhausted->payload)->toBeNull()
        ->and($exhausted->undeliverable_at)->not->toBeNull();
});

it('treats missing and expired rows as successful terminal outcomes', function (): void {
    app(OtpOutboxDelivery::class)->deliver(str_repeat('f', 64));

    [$factor, $attempt, $delivery] = outboxFixture();
    $factor->challenge(new ChallengeRequest($attempt));
    $outbox = AuthChallengeOutbox::query()->firstOrFail();
    DB::table('auth_challenge_outbox')->where('id', $outbox->id)->update([
        'expires_at' => now()->subSecond(),
    ]);

    app(OtpOutboxDelivery::class)->deliver($outbox->opaque_id);

    expect($outbox->refresh()->status)->toBe(OtpOutboxStatus::Undeliverable->value)
        ->and($outbox->payload)->toBeNull()
        ->and($outbox->undeliverable_at)->not->toBeNull()
        ->and($delivery->sent)->toBe([]);
});

it('delivers the exact encrypted target snapshot rather than resolving mutable state', function (): void {
    [$factor, $attempt, $delivery] = outboxFixture();
    $factor->challenge(new ChallengeRequest($attempt));
    $outbox = AuthChallengeOutbox::query()->firstOrFail();
    $payload = requiredOutboxPayload($outbox);

    DB::table('auth_identifiers')->update([
        'value' => 'changed-after-issuance@acme.example',
    ]);

    app(OtpOutboxDelivery::class)->deliver($outbox->opaque_id);

    expect($outbox->refresh()->status)->toBe(OtpOutboxStatus::Delivered->value)
        ->and($outbox->payload)->toBeNull()
        ->and($payload['target'])->not->toBeNull()
        ->and($delivery->lastIdentifier()->value)->toBe('outbox@acme.example')
        ->and($delivery->lastIdentifier()->value)->not->toBe('changed-after-issuance@acme.example')
        ->and($delivery->lastIdentifier()->verified_at)->not->toBeNull();
});

it('terminalizes a transient failure when the deadline crosses during provider IO', function (): void {
    [$factor, $attempt] = outboxFixture();
    $factor->challenge(new ChallengeRequest($attempt));
    $outbox = AuthChallengeOutbox::query()->firstOrFail();
    app()->instance(OtpDelivery::class, new ExpiringThenFailingOtpDelivery());

    app(OtpOutboxDelivery::class)->deliver($outbox->opaque_id);

    expect($outbox->refresh()->status)->toBe(OtpOutboxStatus::Undeliverable->value)
        ->and($outbox->payload)->toBeNull()
        ->and($outbox->undeliverable_at)->not->toBeNull();
});

it('rolls the challenge back when its outbox cannot be persisted', function (): void {
    [$factor, $attempt] = outboxFixture();

    AuthChallengeOutbox::creating(static function (): void {
        throw new RuntimeException('outbox write refused');
    });

    expect(fn () => $factor->challenge(new ChallengeRequest($attempt)))
        ->toThrow(RuntimeException::class, 'outbox write refused')
        ->and(AuthChallenge::query()->count())->toBe(0)
        ->and(AuthChallengeOutbox::query()->count())->toBe(0);
});

it('refuses a synchronous queue before creating delivery state', function (): void {
    $dispatcher = new OtpQueueDispatcher(
        queueFactoryFor(new SyncQueue()),
        app(Fissible\Vouch\Support\DatabaseTime::class),
        'inline',
        'vouch-otp',
    );

    expect(fn () => $dispatcher->assertAsynchronous())
        ->toThrow(InvalidArgumentException::class, 'connection "inline"')
        ->and(fn () => $dispatcher->assertAsynchronous())
        ->toThrow(InvalidArgumentException::class, SyncQueue::class);
});

it('refuses a discarding queue and every inline member of a failover queue', function (): void {
    $time = app(Fissible\Vouch\Support\DatabaseTime::class);
    $null = new OtpQueueDispatcher(
        queueFactoryFor(new NullQueue()),
        $time,
        'discard',
        'vouch-otp',
    );

    expect(fn () => $null->assertAsynchronous())
        ->toThrow(InvalidArgumentException::class, NullQueue::class);

    config()->set('queue.connections.durable-test', [
        'driver' => 'database',
        'connection' => null,
        'table' => 'jobs',
        'queue' => 'default',
        'retry_after' => 60,
    ]);
    config()->set('queue.connections.inline-test', ['driver' => 'sync']);
    config()->set('queue.connections.discard-test', ['driver' => 'null']);
    $manager = new QueueManager(app());
    $manager->addConnector('database', fn (): DatabaseConnector => new DatabaseConnector(app('db')));
    $manager->addConnector('null', fn (): NullConnector => new NullConnector());
    $manager->addConnector('sync', fn (): SyncConnector => new SyncConnector());
    $events = app(Illuminate\Contracts\Events\Dispatcher::class);
    $durable = new OtpQueueDispatcher(
        queueFactoryFor(new FailoverQueue($manager, $events, ['durable-test'])),
        $time,
        'failover-safe',
        'vouch-otp',
    );
    $mixed = new OtpQueueDispatcher(
        queueFactoryFor(new FailoverQueue($manager, $events, ['durable-test', 'inline-test'])),
        $time,
        'failover-mixed',
        'vouch-otp',
    );
    $discarding = new OtpQueueDispatcher(
        queueFactoryFor(new FailoverQueue($manager, $events, ['durable-test', 'discard-test'])),
        $time,
        'failover-discard',
        'vouch-otp',
    );

    $durable->assertAsynchronous();

    expect(fn () => $mixed->assertAsynchronous())
        ->toThrow(InvalidArgumentException::class, 'connection "failover-mixed"')
        ->and(fn () => $mixed->assertAsynchronous())
        ->toThrow(InvalidArgumentException::class, SyncQueue::class)
        ->and(fn () => $discarding->assertAsynchronous())
        ->toThrow(InvalidArgumentException::class, NullQueue::class);
});

it('rechecks queue posture inside dispatch and does not mark a rejected push', function (): void {
    [$factor, $attempt] = outboxFixture();
    $factor->challenge(new ChallengeRequest($attempt));
    $outbox = AuthChallengeOutbox::query()->firstOrFail();
    $outbox->update(['dispatched_at' => null]);
    $dispatcher = new OtpQueueDispatcher(
        queueFactoryFor(new SyncQueue()),
        app(Fissible\Vouch\Support\DatabaseTime::class),
        'inline',
        'vouch-otp',
    );

    expect(fn () => $dispatcher->dispatch($outbox))
        ->toThrow(InvalidArgumentException::class, 'durable asynchronous queue')
        ->and($outbox->refresh()->dispatched_at)->toBeNull();
});

it('rechecks queue posture inside the OTP factor before durable state exists', function (): void {
    $time = app(Fissible\Vouch\Support\DatabaseTime::class);
    $dispatcher = new OtpQueueDispatcher(
        queueFactoryFor(new SyncQueue()),
        $time,
        'inline',
        'vouch-otp',
    );
    $factor = new EmailOtpFactor(
        app(EnrollmentGuard::class),
        app(ClockInterface::class),
        new OtpChallengeOutbox(app('db')->connection(), $dispatcher, $time),
        app(AuthThrottleStore::class),
    );
    $identifier = AuthIdentifier::create([
        'user_id' => 7,
        'type' => 'email',
        'value' => 'driver-inline@acme.example',
        'verified_at' => now(),
    ]);
    $credential = $factor->enroll(7, ['identifier_id' => $identifier->id])->credentials[0];
    $attempt = AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'user_id' => 7,
        'identifier' => $identifier->value,
        'bound_context' => str_repeat('i', 64),
        'expires_at' => now()->addMinutes(10),
    ]);

    expect(fn () => $factor->challenge(new ChallengeRequest($attempt, $credential)))
        ->toThrow(InvalidArgumentException::class, 'durable asynchronous queue')
        ->and(AuthChallenge::query()->count())->toBe(0)
        ->and(AuthChallengeOutbox::query()->count())->toBe(0);
});
