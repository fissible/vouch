<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\Authenticated;
use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Flow\RecoveryGraceStarted;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

const FLOW_BINDING_SOURCE = 'host-session-under-test';

function flowBinding(): string
{
    return SessionBinding::for(FLOW_BINDING_SOURCE, BindingDomain::Attempt);
}

function theFlow(): AuthFlow
{
    return app(AuthFlow::class);
}

/**
 * @param  array<string, mixed>  $document
 */
function flowPolicy(array $document = ['all_of' => ['password']]): void
{
    AuthPolicy::create(['tenant_id' => null, 'scope' => 'login', 'document' => $document, 'posture' => 'friendly']);
}

function flowPassword(int $userId = 7, string $password = 'correct horse battery staple'): void
{
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll($userId, ['password' => $password]);
}

/**
 * @param  array<string, mixed>  $input
 */
function flowBegin(array $input = []): FlowRequest
{
    return new FlowRequest(null, 'begin', $input, flowBinding());
}

/**
 * @param  array<string, mixed>  $input
 */
function flowAdvance(string $handle, array $input, ?string $binding = null, string $action = 'submit'): FlowRequest
{
    return new FlowRequest($handle, $action, $input, $binding ?? flowBinding());
}

/** Begins an attempt and submits the identifier, returning the handle. */
function flowIdentified(int $userId = 7): string
{
    AuthIdentifier::create([
        'user_id' => $userId, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);

    $begun = theFlow()->advance(flowBegin());
    assert($begun instanceof Continuing);
    $handle = $begun->handle;
    assert(is_string($handle));
    theFlow()->advance(flowAdvance($handle, ['identifier' => 'ada@acme.example']));

    return $handle;
}

it('creates a persisted attempt and returns its handle', function (): void {
    $result = theFlow()->advance(flowBegin());
    // assert() for PHPStan narrowing before the property reads; the
    // toBeInstanceOf assertion below is the behavioural check.
    assert($result instanceof Continuing);

    $attempt = AuthAttempt::query()->latest('id')->firstOrFail();

    expect($result)->toBeInstanceOf(Continuing::class)
        ->and($result->handle)->toBe($attempt->handle)
        ->and($attempt->state)->toBe(AttemptState::Initiated)
        ->and($attempt->handle)->toHaveLength(64)
        ->and($attempt->expires_at)->not->toBeNull()
        ->and($attempt->bound_context)->toBe(flowBinding())
        ->and($attempt->bound_context)->not->toContain(FLOW_BINDING_SOURCE);
});

it('issues a distinct handle per attempt', function (): void {
    // A guessable or reused handle plus a matching bound context is an attempt
    // takeover, so this pins that the handle comes from a CSPRNG per call.
    theFlow()->advance(flowBegin());
    theFlow()->advance(flowBegin());

    expect(AuthAttempt::query()->distinct()->count('handle'))->toBe(2);
});

it('echoes no handle when refusing an unknown one', function (): void {
    $result = theFlow()->advance(flowAdvance('not-a-real-handle', []));
    assert($result instanceof Continuing);

    expect($result)->toBeInstanceOf(Continuing::class)
        ->and($result->handle)->toBeNull();
});

it('refuses to advance an attempt from a different bound context', function (): void {
    /*
     * The handle identifies the attempt; it must not also authorize it. This is
     * the test that makes ContextMismatch a security invariant rather than a
     * conditional one.
     */
    flowPolicy();
    flowPassword();

    $begun = theFlow()->advance(flowBegin());
    assert($begun instanceof Continuing);
    $handle = $begun->handle;
    assert(is_string($handle));

    $result = theFlow()->advance(flowAdvance(
        $handle,
        ['identifier' => 'ada@acme.example'],
        SessionBinding::for('a-different-host-session', BindingDomain::Attempt),
    ));
    assert($result instanceof Continuing);

    expect($result)->toBeInstanceOf(Continuing::class)
        ->and($result->handle)->toBeNull();
});

it('authenticates when the policy is satisfied', function (): void {
    flowPolicy();
    flowPassword();

    $handle = flowIdentified();

    $result = theFlow()->advance(flowAdvance($handle, ['password' => 'correct horse battery staple']));
    assert($result instanceof Authenticated);

    expect($result)->toBeInstanceOf(Authenticated::class)
        ->and($result->success->userId)->toBe(7)
        ->and($result->success->amr())->toBe(['password'])
        ->and($result->success->boundContext)->toBe(flowBinding());
});

it('does not rotate any session itself', function (): void {
    // AuthFlow is not session-aware. Authenticated carries the facts;
    // SessionLifecycle performs the rotation, after this returns.
    flowPolicy();
    flowPassword();

    $handle = flowIdentified();
    theFlow()->advance(flowAdvance($handle, ['password' => 'correct horse battery staple']));

    expect(AuthSession::count())->toBe(0);
});

it('opens recovery grace rather than authenticating on a recovery code', function (): void {
    /*
     * Recovery evidence is filtered out of satisfiability by the kernel, so the
     * policy is never satisfied by it. The flow must recognise that and open the
     * constrained capability instead of leaving the user stuck.
     */
    flowPolicy();
    flowPassword();
    $codes = array_map(
        static fn (\Fissible\Vouch\Secrets\OneTimeSecret $secret): string => $secret->reveal(),
        app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)->enroll(7, [])->secrets,
    );

    $handle = flowIdentified();
    $result = theFlow()->advance(flowAdvance($handle, ['code' => $codes[0]], action: 'recover'));
    assert($result instanceof RecoveryGraceStarted);

    expect($result)->toBeInstanceOf(RecoveryGraceStarted::class)
        ->and($result->userId)->toBe(7);
});

it('burns a recovery code only through the store', function (): void {
    // The driver returns a DisableCredential mutation; the flow hands it to
    // transition(). If the flow burned it directly, a later transition failure
    // would leave the code spent and the user unauthenticated.
    flowPolicy();
    flowPassword();
    $codes = array_map(
        static fn (\Fissible\Vouch\Secrets\OneTimeSecret $secret): string => $secret->reveal(),
        app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)->enroll(7, [])->secrets,
    );

    $handle = flowIdentified();
    theFlow()->advance(flowAdvance($handle, ['code' => $codes[0]], action: 'recover'));

    expect(AuthCredential::where('type', 'recovery_code')->whereNull('disabled_at')->count())->toBe(9);
});
