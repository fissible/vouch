<?php

declare(strict_types=1);

use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor;
use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Flow\RecoveryGraceRefused;
use Fissible\Vouch\Flow\RecoveryGraceStarted;
use Fissible\Vouch\Http\FlowResultHandler;
use Fissible\Vouch\Http\FlowResultSerializer;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Recovery\GraceGuard;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Fissible\Vouch\Sessions\SessionRebinder;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session as SessionContract;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * Issue #36 -- the flow needs a way to say grace was refused.
 *
 * #36 stops GraceGuard::start() reviving a revoked session. CredentialRecovery
 * reports that as an ordinary refusal, but the OTHER path that opens grace --
 * a recovery-code login through AuthFlow -- called start() and discarded the
 * answer, so the handler still returned RecoveryGraceStarted.
 *
 * That is the same lie #36 removes, on the path its tests did not reach: the
 * user is told grace opened and every later step refuses, which is precisely
 * the silent half-success the old GraceControllerTest was written to prevent.
 *
 * RecoveryGraceStarted means the flow opened the capability, so returning it
 * when nothing opened is a false success. Continuing would be a different
 * misstatement -- that the flow is still eligible for another challenge, which
 * it is not. The domain has a fourth outcome and it needs its own name.
 *
 * What these pin, deliberately without naming a reason value: the refusal is
 * its own result type, the revoked row is untouched, no capability exists, and
 * nothing rendered to the caller says WHY -- a caller who can tell "revoked"
 * from "no such session" learns which host sessions were once real.
 */

function refusalBinding(string $hostSessionId): string
{
    return SessionBinding::for($hostSessionId, BindingDomain::Session);
}

function refusalAccount(): string
{
    return refusalCodes()[0];
}

/**
 * Enrol the account once and hand back every recovery code it minted.
 *
 * Separate from refusalAccount() because a test needing two usable codes must
 * not enrol twice: the identifier is unique, and a second enrolment fails on
 * the index rather than on anything the test is about.
 *
 * @return list<string>
 */
function refusalCodes(): array
{
    AuthIdentifier::create([
        'user_id' => 7,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => now(),
    ]);

    app(PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);

    AuthPolicy::query()->create([
        'tenant_id' => null,
        'scope' => 'login',
        'document' => ['all_of' => ['password']],
        'posture' => 'friendly',
    ]);

    // Revealed here because recovery codes are stored only as hashes, the way
    // the flow's own recovery tests do it.
    return array_map(
        static fn (\Fissible\Vouch\Secrets\OneTimeSecret $secret): string => $secret->reveal(),
        app(RecoveryCodeFactor::class)->enroll(7, [])->secrets,
    );
}

function refusalHandler(): FlowResultHandler
{
    $guard = auth()->guard('web');
    $session = session()->driver();

    if (! $guard instanceof StatefulGuard) {
        throw new RuntimeException('The web guard is not stateful.');
    }

    if (! $session instanceof SessionContract) {
        throw new RuntimeException('The session driver is not a session.');
    }

    return new FlowResultHandler(
        app(SessionLifecycle::class),
        app(GraceGuard::class),
        $guard,
        $session,
        app(SessionRebinder::class),
        app(\Fissible\Vouch\Flow\ScreenBuilder::class),
    );
}

/** Drive a complete recovery-code login and hand back what the handler returned. */
function completeRecoveryLogin(string $code): \Fissible\Vouch\Flow\FlowResult
{
    session()->start();

    $binding = str_repeat('r', 64);

    $begun = app(AuthFlow::class)->advance(new FlowRequest(null, 'begin', [], $binding));

    if (! $begun instanceof Continuing || $begun->handle === null) {
        throw new RuntimeException('The flow did not begin with a continuing handle.');
    }

    app(AuthFlow::class)->advance(
        new FlowRequest($begun->handle, 'submit', ['identifier' => 'ada@acme.example'], $binding),
    );

    $result = app(AuthFlow::class)->advance(
        new FlowRequest($begun->handle, 'recover', ['code' => $code], $binding),
    );

    return refusalHandler()->handle($result);
}

it('opens grace through a complete recovery-code login', function (): void {
    /*
     * The control, and it has to come first: without it, every refusal below
     * could be a recovery flow that never worked in this harness at all.
     */
    $code = refusalAccount();

    $result = completeRecoveryLogin($code);

    expect($result)->toBeInstanceOf(RecoveryGraceStarted::class)
        ->and(app(GraceGuard::class)->activeFor(session()->getId()))->toBeInstanceOf(AuthSession::class);
});

it('refuses grace through the flow when the host session was revoked', function (): void {
    /*
     * The path that discarded start()'s answer. The recovery code is valid and
     * the flow is willing; the host session it would attach to is finished.
     */
    $code = refusalAccount();

    session()->start();

    AuthSession::create([
        'session_binding' => refusalBinding(session()->getId()),
        'user_id' => 7,
        'amr' => ['password'],
        'revoked_at' => now()->subHour(),
        'revoked_reason' => RevokedReason::AdminRevoked,
    ]);

    $result = completeRecoveryLogin($code);

    expect($result)->toBeInstanceOf(RecoveryGraceRefused::class)
        ->and($result)->not->toBeInstanceOf(RecoveryGraceStarted::class)
        ->and($result)->not->toBeInstanceOf(Continuing::class);
});

it('leaves the revoked row untouched when the flow refuses', function (): void {
    // Refusing must not be a write. The audit record is the reason the row
    // exists in this state at all.
    $code = refusalAccount();

    session()->start();

    AuthSession::create([
        'session_binding' => refusalBinding(session()->getId()),
        'user_id' => 7,
        'amr' => ['password'],
        'revoked_at' => now()->subHour(),
        'revoked_reason' => RevokedReason::AdminRevoked,
    ]);

    $before = requiredRow(DB::table('auth_sessions')
        ->where('session_binding', refusalBinding(session()->getId()))->first());

    completeRecoveryLogin($code);

    $after = requiredRow(DB::table('auth_sessions')
        ->where('session_binding', refusalBinding(session()->getId()))->first());

    expect((array) $after)->toBe((array) $before)
        ->and(app(GraceGuard::class)->activeFor(session()->getId()))->toBeNull();
});

it('does not tell the caller that the binding was revoked', function (): void {
    /*
     * A refusal that says WHY is an oracle: someone who can tell "this session
     * was revoked" from "there is no such session" learns which host sessions
     * were once real, which is exactly what the anonymous grace route is
     * careful not to disclose elsewhere.
     *
     * Asserted over the rendered payload rather than the object, because that
     * is what actually reaches a caller.
     */
    $code = refusalAccount();

    session()->start();

    AuthSession::create([
        'session_binding' => refusalBinding(session()->getId()),
        'user_id' => 7,
        'amr' => ['password'],
        'revoked_at' => now()->subHour(),
        'revoked_reason' => RevokedReason::AdminRevoked,
    ]);

    $result = completeRecoveryLogin($code);
    $rendered = strtolower(json_encode(app(FlowResultSerializer::class)->toArray($result, null)) ?: '');

    // Non-empty, or the containment checks below hold vacuously.
    expect($rendered)->not->toBe('');

    foreach (['revok', 'admin_revoked', 'password_changed', 'superseded'] as $disclosure) {
        expect($rendered)->not->toContain($disclosure);
    }
});

it('renders a refusal distinctly from an opened grace', function (): void {
    /*
     * A caller must be able to act on the difference. Rendering both as
     * 'recovery_grace' would leave the adapter redirecting into a flow that
     * has no capability behind it -- the original defect, one layer out.
     */
    /*
     * Two codes from ONE enrollment rather than two accounts: re-running the
     * fixture would re-create the identifier and collide on its unique index,
     * which is a fixture failure rather than anything about rendering.
     */
    $codes = refusalCodes();

    $opened = app(FlowResultSerializer::class)->toArray(completeRecoveryLogin($codes[0]), null);

    DB::table('auth_sessions')->delete();

    $refusedCode = $codes[1];
    session()->start();

    AuthSession::create([
        'session_binding' => refusalBinding(session()->getId()),
        'user_id' => 7,
        'amr' => ['password'],
        'revoked_at' => now()->subHour(),
        'revoked_reason' => RevokedReason::AdminRevoked,
    ]);

    $refused = app(FlowResultSerializer::class)->toArray(completeRecoveryLogin($refusedCode), null);

    expect($refused['result'] ?? null)->not->toBe($opened['result'] ?? null)
        ->and($refused['result'] ?? null)->not->toBeNull();
});
