<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Flow\RecoveryGraceStarted;
use Fissible\Vouch\Flow\VerificationEqualizer;
use Fissible\Vouch\Http\FlowResultHandler;
use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Tests\Support\RecordingHasher;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Fissible\Vouch\Tests\Support\RecordingGuard;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Support\Facades\Hash;

uses(RefreshDatabase::class);

/*
 * The four surfaces in src/Flow where a surviving mutant would cost something
 * real: the persisted assurance record, the policy predicate that decides which
 * factor a user is offered, the handler branch that separates recovery grace
 * from a login, and the equalizer's dummy digest.
 */

function riskBinding(): string
{
    return SessionBinding::for('risk-surface-session', BindingDomain::Attempt);
}

function riskFlow(): AuthFlow
{
    return app(AuthFlow::class);
}

/** Walk a password login to Authenticated and return the attempt row. */
function riskAuthenticate(): AuthAttempt
{
    AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['password']], 'posture' => 'friendly',
    ]);
    AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);

    $begun = riskFlow()->advance(new FlowRequest(null, 'begin', [], riskBinding()));
    assert($begun instanceof Continuing && is_string($begun->handle));
    $handle = $begun->handle;

    riskFlow()->advance(new FlowRequest($handle, 'submit', ['identifier' => 'ada@acme.example'], riskBinding()));
    riskFlow()->advance(new FlowRequest($handle, 'submit', ['password' => 'correct horse battery staple'], riskBinding()));

    return AuthAttempt::where('handle', $handle)->firstOrFail();
}

it('persists every field of the assurance record', function (): void {
    /*
     * satisfied_factors is the attempt's evidence ledger. It is what
     * existingFactors() rehydrates on the next step and what the assurance
     * evaluator reasons over, so a key dropped here is not a cosmetic loss --
     * it is evidence that silently stops existing.
     *
     * is_multi_factor, user_verified and phishing_resistant are the three that
     * matter most: absent, they rehydrate as their defaults, and a factor that
     * claimed nothing becomes indistinguishable from one that was never asked.
     *
     * Asserted as a complete, ordered key set, because the failure mode is
     * omission and no assertion about a single field can see it.
     */
    $stored = riskAuthenticate()->satisfied_factors;

    // A real check rather than an assertion-then-index: the column is nullable,
    // and an empty ledger is precisely one of the failures under test.
    if ($stored === null || $stored === []) {
        throw new RuntimeException('The flow recorded no satisfied factors at all.');
    }

    expect($stored)->toHaveCount(1);

    $row = $stored[0];

    expect(array_keys($row))->toBe([
        'factor_id',
        'credential_id',
        'kind',
        'strength',
        'is_multi_factor',
        'user_verified',
        'phishing_resistant',
        'authenticator_id',
        'satisfied_at',
    ])
        ->and($row['factor_id'])->toBe('password')
        ->and($row['is_multi_factor'])->toBeFalse()
        ->and($row['user_verified'])->toBeFalse()
        ->and($row['phishing_resistant'])->toBeFalse()
        // A timestamp, not a serialized object: this round-trips through JSON.
        ->and($row['satisfied_at'])->toBeString();
});

it('offers a registered credential type and falls back to password otherwise', function (mixed $stored, string $expected): void {
    /*
     * `is_string($type) && $this->registry->has($type) ? $type : 'password'`.
     *
     * Read as an OR, an unregistered credential type is offered to the user --
     * a challenge screen for a driver that does not exist, which no submission
     * can satisfy. That is a lockout for exactly the users whose credential row
     * is stale, and it is invisible to any test that only enrols real drivers.
     */
    AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['any_of' => ['password', 'totp']], 'posture' => 'friendly',
    ]);
    AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);

    AuthCredential::create([
        'user_id' => 7, 'type' => $stored, 'secret' => 'digest', 'strength' => 'possession',
    ]);

    $begun = riskFlow()->advance(new FlowRequest(null, 'begin', [], riskBinding()));
    assert($begun instanceof Continuing && is_string($begun->handle));

    $next = riskFlow()->advance(
        new FlowRequest($begun->handle, 'submit', ['identifier' => 'ada@acme.example'], riskBinding()),
    );
    assert($next instanceof Continuing);

    /*
     * The DEFAULT option, not mere presence in the list.
     *
     * The first version of this asserted `toContain('password')`, which the
     * policy already guarantees -- `any_of: [password, totp]` offers password no
     * matter what defaultFactorFor() decides. It passed with the predicate
     * inverted and measured nothing. Only the isDefault flag reflects this
     * function's output.
     */
    $default = array_values(array_filter(
        $next->screen->offeredFactors,
        static fn (\Fissible\Vouch\Kernel\Screen\FactorOption $option): bool => $option->isDefault,
    ));

    expect($default)->toHaveCount(1)
        ->and($default[0]->factorId)->toBe($expected);
})->with([
    'registered driver is offered' => ['totp', 'totp'],
    'unregistered type falls back' => ['webauthn_platform', 'password'],
]);

it('opens recovery grace without establishing a session', function (): void {
    /*
     * The handler branch that separates a constrained capability from a login.
     * Collapsed into the default arm it throws; collapsed into the
     * Authenticated arm it would call the host guard, which is precisely the
     * thing recovery grace exists not to do.
     */
    $guard = new RecordingGuard();
    app()->instance(StatefulGuard::class, $guard);

    $screen = app(\Fissible\Vouch\Flow\ScreenBuilder::class)
        ->identify(EnumerationPosture::Friendly);

    $result = app(FlowResultHandler::class)->handle(
        new RecoveryGraceStarted(7, riskBinding(), $screen),
    );

    expect($result)->toBeInstanceOf(RecoveryGraceStarted::class)
        // A grace row opened...
        ->and(AuthSession::whereNotNull('recovery_grace_expires_at')->count())->toBe(1)
        // ...and the host guard never touched. This is the assertion that
        // distinguishes a constrained capability from a login; asserting only
        // the row would pass even if the user had also been signed in.
        ->and($guard->loggedIn)->toBe([]);
});

it('makes the dummy digest once and reuses it', function (): void {
    /*
     * `$this->dummy ??= $this->hasher->make(...)`. With the coalesce removed the
     * placeholder is re-hashed on every equalized request.
     *
     * That is a denial-of-service amplifier rather than a leak: every
     * unknown-identifier submission would pay a full hash construction, which is
     * the most expensive operation in the request, and an attacker chooses how
     * often to trigger it. The equalization still works, so nothing about
     * timing symmetry would notice.
     */
    $hasher = new RecordingHasher();
    Hash::swap($hasher);

    $equalizer = new VerificationEqualizer($hasher);
    $equalizer->equalize(EnumerationPosture::Strict);
    $equalizer->equalize(EnumerationPosture::Strict);
    $equalizer->equalize(EnumerationPosture::Strict);

    expect($hasher->makeCalls)->toBe(1)
        ->and($hasher->checkedAgainst)->toHaveCount(3)
        // Every check ran against the SAME digest -- the point of memoising it.
        ->and(count(array_unique($hasher->checkedAgainst)))->toBe(1);
});

it('does no hashing work at all under a friendly posture', function (): void {
    // The early return. Equalizing under friendly posture would spend a hash on
    // every request for a leak that posture does not have.
    $hasher = new RecordingHasher();

    (new VerificationEqualizer($hasher))->equalize(EnumerationPosture::Friendly);

    expect($hasher->makeCalls)->toBe(0)
        ->and($hasher->checkedAgainst)->toBe([]);
});

it('dispatches each result variant to its own branch and no other', function (): void {
    /*
     * Both FlowResultHandler and FlowResultSerializer discriminate with
     * `match (true)`. Read as `match (false)` the arms invert: the FIRST arm
     * whose condition is FALSE wins, so a Continuing result -- which is not
     * Authenticated -- falls into the Authenticated branch and establishes a
     * session for a flow that has not finished authenticating.
     *
     * That is the single worst mis-dispatch available in this file, and it is a
     * one-token change. Continuing is the variant that proves it: it must pass
     * through untouched, with the host guard never invoked.
     */
    $guard = new RecordingGuard();
    app()->instance(StatefulGuard::class, $guard);

    $screen = app(\Fissible\Vouch\Flow\ScreenBuilder::class)->identify(EnumerationPosture::Friendly);
    $continuing = new \Fissible\Vouch\Flow\Continuing($screen, 'handle-1');

    $handled = app(FlowResultHandler::class)->handle($continuing);

    expect($handled)->toBe($continuing)
        ->and($guard->loggedIn)->toBe([])
        ->and(AuthSession::count())->toBe(0);
});

it('serializes a continuing result as continuing, never as an outcome', function (): void {
    /*
     * The serializer's half of the same discriminator. Inverted, a still-running
     * attempt is described to the client as 'authenticated' -- a success-shaped
     * envelope for a flow that produced no session, which a client has no way to
     * tell from a real one.
     */
    $screen = app(\Fissible\Vouch\Flow\ScreenBuilder::class)->identify(EnumerationPosture::Friendly);

    $payload = app(\Fissible\Vouch\Http\FlowResultSerializer::class)
        ->toArray(new \Fissible\Vouch\Flow\Continuing($screen, 'handle-1'), '/dashboard');

    expect($payload['result'])->toBe('continuing')
        ->and($payload['handle'])->toBe('handle-1')
        // And no returnTo: a redirect target on an unfinished attempt is an open
        // redirect handed out before authentication.
        ->and($payload)->not->toHaveKey('returnTo');
});

/*
 * OPEN: AuthFlow:200 -- `$this->equalizer->equalize($posture)` on the
 * NoCredential path -- has no test and is NOT ruled.
 *
 * VerificationEqualizer's own tests prove it does the work; what is missing is
 * proof that AuthFlow ASKS for it here, where a driver reported NoCredential and
 * therefore did no hashing. Under strict posture that speed difference is the
 * account-existence oracle the equalizer exists to close.
 *
 * An attempt at this test recorded zero hasher calls, meaning the injected
 * equalizer was not the one the flow used -- the container returned a differently
 * constructed AuthFlow despite forgetInstance(). The seam needs establishing
 * before the assertion can mean anything, and a test that cannot observe the call
 * would be exactly the vacuous control this audit keeps finding.
 *
 * Left undone and recorded rather than committed green.
 */

it('does not authenticate when no policy is configured', function (): void {
    /*
     * targetState() returns FactorSatisfied when policyFor() finds nothing.
     * Without that early return the method falls through to evaluate a null
     * policy -- and whatever it produced, "no policy" must never mean "any
     * credential authenticates". A host that has not configured a login policy
     * has not authorised anyone.
     */
    AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);

    $begun = riskFlow()->advance(new FlowRequest(null, 'begin', [], riskBinding()));
    assert($begun instanceof Continuing && is_string($begun->handle));

    riskFlow()->advance(new FlowRequest($begun->handle, 'submit', ['identifier' => 'ada@acme.example'], riskBinding()));

    $result = riskFlow()->advance(
        new FlowRequest($begun->handle, 'submit', ['password' => 'correct horse battery staple'], riskBinding()),
    );

    expect($result)->not->toBeInstanceOf(\Fissible\Vouch\Flow\Authenticated::class);
});
