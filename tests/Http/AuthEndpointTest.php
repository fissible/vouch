<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Tests\Support\RecordingGuard;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * Function-scoped rather than $this->guard: PHPStan cannot resolve $this inside
 * a Pest closure past the base PHPUnit TestCase. Rebound unconditionally in
 * beforeEach, and Pest builds a fresh app per test, so no state leaks between
 * tests.
 */
function recordingGuard(?RecordingGuard $set = null): RecordingGuard
{
    static $guard = null;

    if ($set !== null) {
        $guard = $set;
    }

    assert($guard instanceof RecordingGuard);

    return $guard;
}

beforeEach(function (): void {
    recordingGuard(new RecordingGuard());
    app()->instance(StatefulGuard::class, recordingGuard());

    AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['password']], 'posture' => 'strict',
    ]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'a-real-password']);
    AuthIdentifier::create(['user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now()]);
});

/*
 * The controller is invoked directly, on ONE shared session.
 *
 * Laravel's test client does not carry response cookies between calls, and a
 * plaintext session cookie is re-encrypted on the way in — both verified rather
 * than assumed. Vouch binds an attempt to its session, so every multi-step flow
 * through the test client dies on a context mismatch at step two.
 *
 * That failure mode is silent in the worst way: two flows that both die on
 * context mismatch return IDENTICAL refusals, so an enumeration test comparing
 * them would pass while proving nothing. Invoking the controller keeps the
 * session real and the assertions meaningful. Route registration is asserted
 * separately below.
 */
function vouchSession(): \Illuminate\Session\Store
{
    static $store = null;

    if ($store === null) {
        $store = new \Illuminate\Session\Store(
            'vouch_test_session',
            new \Illuminate\Session\ArraySessionHandler(120),
            substr(str_repeat('vouchtestsession', 4), 0, 40),
        );
        $store->start();
    }

    return $store;
}

/**
 * @param  array<string, mixed>  $payload
 */
function callAuthResponse(array $payload): \Illuminate\Http\JsonResponse
{
    $request = \Illuminate\Http\Request::create('/vouch/auth', 'POST', [], [], [], [], (string) json_encode($payload));
    $request->headers->set('Content-Type', 'application/json');
    $request->setLaravelSession(vouchSession());

    return app(\Fissible\Vouch\Http\AuthController::class)($request);
}

/**
 * @param  array<string, mixed>  $payload
 * @return array{result: string, handle: string|null, screen: array<string, mixed>}
 */
function callAuth(array $payload): array
{
    $response = callAuthResponse($payload);

    /** @var array{result: string, handle: string|null, screen: array<string, mixed>} $decoded */
    $decoded = json_decode((string) $response->getContent(), true);

    return $decoded;
}

it('registers the endpoint that the flow is reached through', function (): void {
    // The controller is exercised directly below; this is what pins that it is
    // actually routable, so the two together cover what one cannot.
    expect(\Illuminate\Support\Facades\Route::has('vouch.auth'))->toBeTrue()
        ->and(\Illuminate\Support\Facades\Route::has('vouch.recovery.enroll'))->toBeTrue()
        ->and(\Illuminate\Support\Facades\Route::has('vouch.recovery.complete'))->toBeTrue();
});

it('begins an attempt and returns a screen with a handle', function (): void {
    $result = callAuth([]);

    expect($result['result'])->toBe('continuing')
        ->and(data_get($result, 'screen.step'))->toBe('identify')
        ->and(data_get($result, 'screen.retry'))->toBeNull()
        ->and($result['handle'])->toBeString()->toHaveLength(64);
});

it('carries the submitted action through to factor selection', function (): void {
    /*
     * `action` reaches exactly one decision: AuthFlow::selectFactor()'s
     * `=== 'recover'` branch, which is what lets a user submit a recovery code
     * instead of the factor the policy would otherwise offer. Nothing asserted
     * that the controller passes it on. Negating the ternary that reads it —
     * `is_string($action) ? null : $action` — silently discards every well-formed
     * action, so recovery through the endpoint stops working while the other
     * 700-odd tests stay green, because none of them sends one.
     *
     * Asserted end to end through the OUTCOME rather than by inspecting the
     * request: with the action carried, a recovery code opens grace; without it
     * the flow selects the default factor instead and the same code is refused
     * as a bad password.
     */
    $codes = array_map(
        static fn (\Fissible\Vouch\Secrets\OneTimeSecret $secret): string => $secret->reveal(),
        app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)->enroll(7, [])->secrets,
    );

    $begun = callAuth([]);
    $handle = $begun['handle'];

    callAuth(['handle' => $handle, 'action' => 'submit', 'input' => ['identifier' => 'ada@acme.example']]);

    $recovered = callAuth(['handle' => $handle, 'action' => 'recover', 'input' => ['code' => $codes[0]]]);

    expect($recovered['result'])->toBe('recovery_grace');
});

it('returns the same shaped refusal whether or not the identifier exists', function (): void {
    /*
     * The enumeration boundary, compared at the SAME step. An unknown
     * identifier deliberately still advances to a challenge screen — refusing
     * at identify would make the flow visibly stop for unknown accounts
     * regardless of what the message said — so the comparison that matters is
     * a rejected credential for a known user against one for an unknown user.
     * Under strict posture those must be indistinguishable.
     */
    $known = callAuth([]);
    callAuth(['handle' => $known['handle'], 'input' => ['identifier' => 'ada@acme.example']]);
    $knownRejected = callAuth(['handle' => $known['handle'], 'input' => ['password' => 'wrong']]);

    $unknown = callAuth([]);
    callAuth(['handle' => $unknown['handle'], 'input' => ['identifier' => 'nobody@acme.example']]);
    $unknownRejected = callAuth(['handle' => $unknown['handle'], 'input' => ['password' => 'wrong']]);

    expect(data_get($knownRejected, 'screen.errors'))->toBe(data_get($unknownRejected, 'screen.errors'))
        ->and($knownRejected['result'])->toBe($unknownRejected['result'])
        ->and(data_get($knownRejected, 'screen.step'))->toBe(data_get($unknownRejected, 'screen.step'));
});

it('echoes no handle back for an unknown one', function (): void {
    expect(callAuth(['handle' => str_repeat('f', 64), 'input' => []])['handle'])->toBeNull();
});

it('keeps retry null when no throttle state was measured', function (): void {
    expect(data_get(callAuth([]), 'screen.retry'))->toBeNull();
});

it('publishes only posture-shaped measured retry for known and unknown identifiers', function (): void {
    $refusals = [];

    foreach (['ada@acme.example', 'nobody@acme.example'] as $identifier) {
        $begun = callAuth([]);
        callAuth([
            'handle' => $begun['handle'],
            'input' => ['identifier' => $identifier],
        ]);

        for ($failure = 1; $failure <= 6; $failure++) {
            $refusal = callAuth([
                'handle' => $begun['handle'],
                'input' => ['password' => 'wrong'],
            ]);

            if ($failure < 5) {
                expect(data_get($refusal, 'screen.retry'))->toBeNull();
            }
        }

        $refusals[] = $refusal;
    }

    $knownRetry = data_get($refusals[0], 'screen.retry');
    $unknownRetry = data_get($refusals[1], 'screen.retry');

    if (! is_array($knownRetry) || ! is_array($unknownRetry)) {
        throw new RuntimeException('The sixth failure did not expose measured retry state.');
    }

    expect(data_get($refusals[0], 'screen.errors'))
        ->toBe(data_get($refusals[1], 'screen.errors'))
        ->and(array_keys($knownRetry))->toBe([
            'attemptsRemaining',
            'lockedUntil',
            'retryAfter',
        ])
        ->and(array_keys($unknownRetry))->toBe([
            'attemptsRemaining',
            'lockedUntil',
            'retryAfter',
        ])
        ->and(data_get($knownRetry, 'attemptsRemaining'))->toBeNull()
        ->and(data_get($unknownRetry, 'attemptsRemaining'))->toBeNull()
        ->and(data_get($knownRetry, 'lockedUntil'))->toBeNull()
        ->and(data_get($unknownRetry, 'lockedUntil'))->toBeNull()
        ->and(data_get($knownRetry, 'retryAfter'))->toBeString()
        ->and(data_get($unknownRetry, 'retryAfter'))->toBeString();
});

it('authenticates through the endpoint and logs in only after the record exists', function (): void {
    /*
     * Step 3 of the fail-closed protocol. The guard double records how many
     * auth_sessions rows existed at the moment of login: if login ran first,
     * that count would be zero.
     */
    $begin = callAuth([]);
    callAuth(['handle' => $begin['handle'], 'input' => ['identifier' => 'ada@acme.example']]);
    $done = callAuth(['handle' => $begin['handle'], 'input' => ['password' => 'a-real-password']]);

    expect($done['result'])->toBe('authenticated')
        ->and(recordingGuard()->loggedIn)->toBe([7])
        ->and(recordingGuard()->sessionRowsAtLogin)->toBe([1]);
});

it('returns 200 for every well-formed outcome, whatever the cause', function (): void {
    /*
     * The status-code half of the enumeration boundary, and the one a test
     * reading only the decoded body cannot see. If a rejected credential
     * returned 422 while a fresh screen returned 200, strict posture would be
     * defeated by `curl -i` regardless of how carefully the body was filtered.
     */
    $begin = callAuthResponse([]);
    $handle = data_get(callAuth([]), 'handle');
    $identified = callAuthResponse(['handle' => $handle, 'input' => ['identifier' => 'ada@acme.example']]);
    $rejected = callAuthResponse(['handle' => $handle, 'input' => ['password' => 'wrong']]);
    $badHandle = callAuthResponse(['handle' => str_repeat('f', 64), 'input' => []]);
    $unknownUser = callAuthResponse(['handle' => data_get(callAuth([]), 'handle'), 'input' => ['identifier' => 'nobody@acme.example']]);

    expect($begin->getStatusCode())->toBe(200)
        ->and($identified->getStatusCode())->toBe(200)
        ->and($rejected->getStatusCode())->toBe(200)
        ->and($badHandle->getStatusCode())->toBe(200)
        ->and($unknownUser->getStatusCode())->toBe(200);
});

it('refuses to handle a FlowResult variant nothing knows about', function (): void {
    /*
     * PHP has no sealed interfaces. Falling through would silently skip session
     * rotation on a successful authentication, leaving a user who appears
     * logged in and holds no record.
     */
    $rogue = new class implements \Fissible\Vouch\Flow\FlowResult {};

    app(\Fissible\Vouch\Http\FlowResultHandler::class)->handle($rogue);
})->throws(\Fissible\Vouch\Flow\UnknownFlowResult::class);

it('refuses to serialize a FlowResult variant nothing knows about', function (): void {
    $rogue = new class implements \Fissible\Vouch\Flow\FlowResult {};

    app(\Fissible\Vouch\Http\FlowResultSerializer::class)->toArray($rogue);
})->throws(\Fissible\Vouch\Flow\UnknownFlowResult::class);
