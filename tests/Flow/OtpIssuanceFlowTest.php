<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Factors\ChallengeIssuanceIntent;
use Fissible\Vouch\Factors\ChallengeIssuanceTicket;
use Fissible\Vouch\Factors\ChallengeIssuer;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\Drivers\SmsOtpFactor;
use Fissible\Vouch\Jobs\DeliverOtpChallenge;
use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthChallengeOutbox;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Notifications\OtpOutboxDelivery;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Notifications\UnconfiguredOtpDelivery;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\RecordingGuard;
use Fissible\Vouch\Throttle\IssuancePermission;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Queue\Factory;
use Illuminate\Contracts\Queue\Queue as QueueContract;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Queue\SyncQueue;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;

uses(RefreshDatabase::class);

function issuanceSession(): Store
{
    static $sequence = 0;
    $sequence++;
    $session = new Store(
        'vouch_issuance_session',
        new ArraySessionHandler(120),
        str_pad('issuance' . $sequence, 40, 'x'),
    );
    $session->start();

    return $session;
}

/**
 * @param array<string, mixed> $payload
 * @return array<string, mixed>
 */
function issuanceEndpoint(array $payload, Store $session): array
{
    $request = Illuminate\Http\Request::create(
        '/vouch/auth',
        'POST',
        [],
        [],
        [],
        ['REMOTE_ADDR' => '198.51.100.24', 'HTTP_USER_AGENT' => 'Vouch OTP test'],
        (string) json_encode($payload),
    );
    $request->headers->set('Content-Type', 'application/json');
    $request->setLaravelSession($session);

    $response = app(Fissible\Vouch\Http\AuthController::class)($request);
    $decoded = json_decode((string) $response->getContent(), true);

    if (! is_array($decoded)) {
        throw new RuntimeException('The OTP endpoint did not return a JSON object.');
    }

    $result = [];

    foreach ($decoded as $key => $value) {
        if (! is_string($key)) {
            throw new RuntimeException('The OTP endpoint returned a non-object JSON shape.');
        }

        $result[$key] = $value;
    }

    return $result;
}

function bindIssuanceDelivery(?ArrayOtpDelivery $delivery = null): ArrayOtpDelivery
{
    $delivery ??= new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);

    foreach ([
        ChallengeIssuer::class,
        AuthFlow::class,
        EmailOtpFactor::class,
        SmsOtpFactor::class,
        Fissible\Vouch\Factors\FactorRegistry::class,
    ] as $service) {
        app()->forgetInstance($service);
    }

    return $delivery;
}

/** @return array{string, string} */
function otpFactorIdentity(string $factor): array
{
    return match ($factor) {
        'email_otp' => ['email', 'flow-otp@acme.example'],
        'sms_otp' => ['phone', '+15550123456'],
        default => throw new InvalidArgumentException('Unknown OTP test factor.'),
    };
}

beforeEach(function (): void {
    app()->instance(StatefulGuard::class, new RecordingGuard());
});

it('does not charge or issue merely for rendering the identify screen', function (): void {
    bindIssuanceDelivery();
    $session = issuanceSession();

    $begin = issuanceEndpoint([], $session);

    expect($begin['result'])->toBe('continuing')
        ->and(data_get($begin, 'screen.step'))->toBe('identify')
        ->and(DB::table('auth_throttle_counters')->where('dimension', 'issuance')->count())->toBe(0)
        ->and(AuthChallenge::query()->count())->toBe(0)
        ->and(AuthChallengeOutbox::query()->count())->toBe(0);

    Queue::assertNothingPushed();
});

it('cannot complete a refused issuance ticket even if a caller presents it directly', function (): void {
    bindIssuanceDelivery();
    $session = issuanceSession();
    $begin = issuanceEndpoint([], $session);
    $attempt = AuthAttempt::query()->where('handle', $begin['handle'])->sole();
    $ticket = new ChallengeIssuanceTicket(
        new ChallengeIssuanceIntent(
            attemptId: $attempt->id,
            submittedIdentifier: 'refused@acme.example',
            factorId: 'email_otp',
            action: 'identify',
            tenantId: null,
            clientIp: '198.51.100.24',
            clientUserAgent: 'Vouch OTP test',
        ),
        IssuancePermission::Refused,
    );

    expect(app(ChallengeIssuer::class)->complete($ticket, $attempt))->toBeNull()
        ->and(AuthChallenge::query()->count())->toBe(0)
        ->and(AuthChallengeOutbox::query()->count())->toBe(0);

    Queue::assertNothingPushed();
});

it('issues and verifies each OTP factor through the public endpoint', function (string $factor): void {
    $delivery = bindIssuanceDelivery();
    [$identifierType, $identifierValue] = otpFactorIdentity($factor);
    AuthPolicy::create([
        'tenant_id' => null,
        'scope' => 'login',
        'document' => ['all_of' => [$factor]],
        'posture' => 'strict',
    ]);
    $identifier = AuthIdentifier::create([
        'user_id' => 7,
        'type' => $identifierType,
        'value' => $identifierValue,
        'verified_at' => now(),
    ]);
    app(Fissible\Vouch\Factors\FactorRegistry::class)
        ->get($factor)
        ->enroll(7, ['identifier_id' => $identifier->id]);

    $session = issuanceSession();
    $begin = issuanceEndpoint([], $session);
    $identified = issuanceEndpoint([
        'handle' => $begin['handle'],
        'action' => 'submit',
        'input' => ['identifier' => $identifierValue, 'factor' => $factor],
    ], $session);

    $challenge = AuthChallenge::query()->sole();
    $outbox = AuthChallengeOutbox::query()->sole();

    expect($identified['result'])->toBe('continuing')
        ->and(data_get($identified, 'screen.step'))->toBe('challenge')
        ->and($challenge->factor_type)->toBe($factor)
        ->and($challenge->credential_id)->not->toBeNull()
        ->and($delivery->sent)->toBe([])
        ->and($outbox->status)->toBe(OtpOutboxStatus::Pending->value);

    app(OtpOutboxDelivery::class)->deliver($outbox->opaque_id);
    $code = $delivery->lastCode();
    $done = issuanceEndpoint([
        'handle' => $begin['handle'],
        'action' => 'submit',
        'input' => ['factor' => $factor, 'code' => $code],
    ], $session);

    $challengeCount = AuthChallenge::query()->count();
    issuanceEndpoint([
        'handle' => $begin['handle'],
        'action' => 'resend',
        'input' => ['factor' => $factor],
    ], $session);

    expect($delivery->lastIdentifier()->id)->toBe($identifier->id)
        ->and($delivery->lastIdentifier()->type)->toBe($identifier->type)
        ->and($delivery->lastIdentifier()->value)->toBe($identifier->value)
        ->and(password_verify($code, $challenge->code_hash))->toBeTrue()
        ->and($done['result'])->toBe('authenticated')
        ->and(AuthChallenge::query()->count())->toBe($challengeCount);
})->with(['email OTP' => ['email_otp'], 'SMS OTP' => ['sms_otp']]);

it('issues the next OTP only after the first factor in an all-of policy succeeds', function (): void {
    $delivery = bindIssuanceDelivery();
    AuthPolicy::create([
        'tenant_id' => null,
        'scope' => 'login',
        'document' => ['all_of' => ['password', 'email_otp']],
        'posture' => 'strict',
    ]);
    $identifier = AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'mfa-otp@acme.example', 'verified_at' => now(),
    ]);
    app(Fissible\Vouch\Factors\Drivers\PasswordFactor::class)
        ->enroll(7, ['password' => 'correct horse battery staple']);
    app(EmailOtpFactor::class)->enroll(7, ['identifier_id' => $identifier->id]);
    $session = issuanceSession();
    $begin = issuanceEndpoint([], $session);
    issuanceEndpoint([
        'handle' => $begin['handle'],
        'input' => ['identifier' => $identifier->value],
    ], $session);

    expect(AuthChallenge::query()->count())->toBe(0);

    $next = issuanceEndpoint([
        'handle' => $begin['handle'],
        'input' => ['factor' => 'password', 'password' => 'correct horse battery staple'],
    ], $session);
    $outbox = AuthChallengeOutbox::query()->sole();

    expect($next['result'])->toBe('continuing')
        ->and(AuthChallenge::query()->sole()->factor_type)->toBe('email_otp')
        ->and($delivery->sent)->toBe([]);

    app(OtpOutboxDelivery::class)->deliver($outbox->opaque_id);
    $done = issuanceEndpoint([
        'handle' => $begin['handle'],
        'input' => ['factor' => 'email_otp', 'code' => $delivery->lastCode()],
    ], $session);

    expect($done['result'])->toBe('authenticated');
});

it('charges known and nonexistent identifiers identically before target resolution', function (): void {
    bindIssuanceDelivery();
    AuthPolicy::create([
        'tenant_id' => null,
        'scope' => 'login',
        'document' => ['all_of' => ['email_otp']],
        'posture' => 'strict',
    ]);
    $identifier = AuthIdentifier::create([
        'user_id' => 7,
        'type' => 'email',
        'value' => 'known-issuance@acme.example',
        'verified_at' => now(),
    ]);
    app(EmailOtpFactor::class)->enroll(7, ['identifier_id' => $identifier->id]);

    $sixth = [];

    foreach ([$identifier->value, 'unknown-issuance@acme.example'] as $value) {
        for ($event = 1; $event <= 6; $event++) {
            $session = issuanceSession();
            $begin = issuanceEndpoint([], $session);
            $result = issuanceEndpoint([
                'handle' => $begin['handle'],
                'input' => ['identifier' => $value, 'factor' => 'email_otp'],
            ], $session);

            if ($event === 6) {
                $sixth[] = $result['screen'];
            }
        }
    }

    expect($sixth[0])->toEqual($sixth[1])
        ->and(DB::table('auth_throttle_counters')->where('dimension', 'issuance')->pluck('count')->all())
        ->toBe([5, 5])
        ->and(AuthChallenge::query()->count())->toBe(10);

    Queue::assertPushedTimes(DeliverOtpChallenge::class, 10);
});

it('charges resend once and reuses a still-pending challenge without resetting attempts', function (): void {
    bindIssuanceDelivery();
    AuthPolicy::create([
        'tenant_id' => null,
        'scope' => 'login',
        'document' => ['all_of' => ['email_otp']],
        'posture' => 'strict',
    ]);
    $identifier = AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'resend@acme.example', 'verified_at' => now(),
    ]);
    app(EmailOtpFactor::class)->enroll(7, ['identifier_id' => $identifier->id]);
    $session = issuanceSession();
    $begin = issuanceEndpoint([], $session);
    issuanceEndpoint([
        'handle' => $begin['handle'],
        'input' => ['identifier' => $identifier->value, 'factor' => 'email_otp'],
    ], $session);
    $first = AuthChallenge::query()->sole();
    $first->update(['attempts' => 2]);

    issuanceEndpoint([
        'handle' => $begin['handle'],
        'action' => 'resend',
        'input' => ['factor' => 'email_otp'],
    ], $session);

    expect(AuthChallenge::query()->count())->toBe(1)
        ->and($first->refresh()->attempts)->toBe(2)
        ->and(AuthChallengeOutbox::query()->count())->toBe(1)
        ->and(DB::table('auth_throttle_counters')->where('dimension', 'issuance')->value('count'))
        ->toBe(2);
});

it('creates a fresh challenge only after the prior delivery is terminal', function (): void {
    $delivery = bindIssuanceDelivery();
    AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['email_otp']], 'posture' => 'strict',
    ]);
    $identifier = AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'terminal-resend@acme.example', 'verified_at' => now(),
    ]);
    app(EmailOtpFactor::class)->enroll(7, ['identifier_id' => $identifier->id]);
    $session = issuanceSession();
    $begin = issuanceEndpoint([], $session);
    issuanceEndpoint([
        'handle' => $begin['handle'],
        'input' => ['identifier' => $identifier->value, 'factor' => 'email_otp'],
    ], $session);
    $firstOutbox = AuthChallengeOutbox::query()->sole();
    app(OtpOutboxDelivery::class)->deliver($firstOutbox->opaque_id);

    issuanceEndpoint([
        'handle' => $begin['handle'],
        'action' => 'resend',
        'input' => ['factor' => 'email_otp'],
    ], $session);

    expect($delivery->sent)->toHaveCount(1)
        ->and(AuthChallenge::query()->count())->toBe(2)
        ->and(AuthChallengeOutbox::query()->count())->toBe(2)
        ->and(AuthChallengeOutbox::query()->where('status', 'pending')->count())->toBe(1)
        ->and(DB::table('auth_throttle_counters')->where('dimension', 'issuance')->value('count'))
        ->toBe(2);
});

it('uses a durable non-delivering decoy when target selection is ambiguous', function (): void {
    $delivery = bindIssuanceDelivery();
    AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['email_otp']], 'posture' => 'strict',
    ]);
    $identifier = AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'ambiguous@acme.example', 'verified_at' => now(),
    ]);
    $second = AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'ambiguous+2@acme.example', 'verified_at' => now(),
    ]);
    app(EmailOtpFactor::class)->enroll(7, ['identifier_id' => $identifier->id]);
    app(EmailOtpFactor::class)->enroll(7, ['identifier_id' => $second->id]);
    $session = issuanceSession();
    $begin = issuanceEndpoint([], $session);
    issuanceEndpoint([
        'handle' => $begin['handle'],
        'input' => ['identifier' => $identifier->value, 'factor' => 'email_otp'],
    ], $session);

    $challenge = AuthChallenge::query()->sole();
    $outbox = AuthChallengeOutbox::query()->sole();

    expect($challenge->is_decoy)->toBeTrue()
        ->and($challenge->credential_id)->toBeNull();

    app(OtpOutboxDelivery::class)->deliver($outbox->opaque_id);

    expect($delivery->sent)->toBe([])
        ->and(AuthChallengeOutbox::query()->count())->toBe(0);
});

it('refuses an unconfigured transport before charging either identifier', function (): void {
    app()->bind(OtpDelivery::class, UnconfiguredOtpDelivery::class);
    app()->forgetInstance(ChallengeIssuer::class);
    app()->forgetInstance(AuthFlow::class);
    AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['email_otp']], 'posture' => 'strict',
    ]);

    foreach (['real@acme.example', 'missing@acme.example'] as $value) {
        $session = issuanceSession();
        $begin = issuanceEndpoint([], $session);

        expect(fn () => issuanceEndpoint([
            'handle' => $begin['handle'],
            'input' => ['identifier' => $value, 'factor' => 'email_otp'],
        ], $session))->toThrow(RuntimeException::class, 'No OTP delivery is configured');
    }

    expect(DB::table('auth_throttle_counters')->where('dimension', 'issuance')->count())->toBe(0);
});

it('refuses an inline queue before charging or creating a challenge', function (): void {
    bindIssuanceDelivery();
    $factory = new class implements Factory
    {
        public function connection($name = null): QueueContract
        {
            return new SyncQueue();
        }
    };
    app()->instance(Factory::class, $factory);

    foreach ([
        Fissible\Vouch\Notifications\OtpQueueDispatcher::class,
        Fissible\Vouch\Notifications\OtpChallengeOutbox::class,
        ChallengeIssuer::class,
        AuthFlow::class,
        EmailOtpFactor::class,
        Fissible\Vouch\Factors\FactorRegistry::class,
    ] as $service) {
        app()->forgetInstance($service);
    }

    AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['email_otp']], 'posture' => 'strict',
    ]);
    $session = issuanceSession();
    $begin = issuanceEndpoint([], $session);

    expect(fn () => issuanceEndpoint([
        'handle' => $begin['handle'],
        'input' => ['identifier' => 'nobody@acme.example', 'factor' => 'email_otp'],
    ], $session))->toThrow(InvalidArgumentException::class, 'durable asynchronous queue')
        ->and(DB::table('auth_throttle_counters')->where('dimension', 'issuance')->count())->toBe(0)
        ->and(AuthChallenge::query()->count())->toBe(0);
});
