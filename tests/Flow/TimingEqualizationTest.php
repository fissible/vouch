<?php

declare(strict_types=1);

use Fissible\Vouch\Http\AuthController;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Tests\Support\CountingHasher;
use Fissible\Vouch\Tests\Support\RecordingGuard;
use Fissible\Vouch\Tests\Support\RecordingHasher;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Hash;

uses(RefreshDatabase::class);

function countingHasher(?CountingHasher $set = null): CountingHasher
{
    static $hasher = null;

    if ($set !== null) {
        $hasher = $set;
    }

    assert($hasher instanceof CountingHasher);

    return $hasher;
}

function timingSession(): Store
{
    return new Store('timing', new ArraySessionHandler(120), substr(str_repeat('timingprobesession', 3), 0, 40));
}

/**
 * @param  array<string, mixed>  $payload
 * @return array{result: string, handle: string|null, screen: array<string, mixed>}
 */
function timingCall(array $payload, Store $session): array
{
    $request = Request::create('/vouch/auth', 'POST', [], [], [], [], (string) json_encode($payload));
    $request->headers->set('Content-Type', 'application/json');
    $request->setLaravelSession($session);

    /** @var array{result: string, handle: string|null, screen: array<string, mixed>} $decoded */
    $decoded = json_decode((string) app(AuthController::class)($request)->getContent(), true);

    return $decoded;
}

/** Runs a flow to a rejected credential and returns the verifications performed. */
function verificationsFor(string $identifier): int
{
    $session = timingSession();
    $session->start();

    $begin = timingCall([], $session);
    timingCall(['handle' => $begin['handle'], 'input' => ['identifier' => $identifier]], $session);

    countingHasher()->checks = 0;
    timingCall(['handle' => $begin['handle'], 'input' => ['password' => 'wrong']], $session);

    return countingHasher()->checks;
}

beforeEach(function (): void {
    /*
     * Hash::swap(), not app()->instance('hash', ...): the facade caches its
     * resolved root, so rebinding the container key leaves an already-resolved
     * facade pointing at the real hasher — and the counter silently reads zero.
     */
    $real = Hash::driver();
    assert($real instanceof Hasher);
    countingHasher(new CountingHasher($real));
    Hash::swap(countingHasher());
    app()->instance(Hasher::class, countingHasher());
    app()->instance(StatefulGuard::class, new RecordingGuard());

    AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['password']], 'posture' => 'strict',
    ]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'a-real-password']);
    AuthIdentifier::create(['user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now()]);
});

it('performs exactly one verification for a known identifier with a wrong password', function (): void {
    expect(verificationsFor('ada@acme.example'))->toBe(1);
});

it('performs exactly one verification for an unknown identifier too', function (): void {
    /*
     * The control. Without the dummy verify this is 0, and the difference is
     * measurable over a handful of requests -- reconstructing exactly the
     * account-existence oracle strict posture exists to deny.
     */
    expect(verificationsFor('nobody@acme.example'))->toBe(1);
});

it('performs the same work for both, which is the property that matters', function (): void {
    expect(verificationsFor('ada@acme.example'))->toBe(verificationsFor('nobody@acme.example'));
});

it('does not equalize under friendly posture', function (): void {
    // Proves the strict assertions measure posture rather than a component that
    // always burns a hash regardless.
    AuthPolicy::query()->update(['posture' => 'friendly']);

    expect(verificationsFor('nobody@acme.example'))->toBe(0);
});

it('still performs one verification under a non-bcrypt hasher (compatibility only)', function (): void {
    /*
     * COMPATIBILITY COVERAGE, not the proof of the timing-inversion safeguard.
     * It shows the equalizer still does its work under Argon; it does NOT show
     * the digest came from the active hasher, because it errors before reaching
     * that question. The provenance proof is the sentinel test below.
     */
    config(['hashing.driver' => 'argon2id']);
    // A fresh manager: the facade root is already the double from beforeEach,
    // and the double has no driver().
    $argon = (new \Illuminate\Hashing\HashManager(app()))->driver('argon2id');
    assert($argon instanceof Hasher);
    countingHasher(new CountingHasher($argon));
    Hash::swap(countingHasher());
    app()->instance(Hasher::class, countingHasher());

    /*
     * VerificationEqualizer captures its hasher at construction and AuthFlow is
     * a singleton, so swapping the binding does not reach an already-resolved
     * instance. Correct in production -- one hasher per application -- but the
     * test has to force a rebuild to exercise the new driver.
     */
    app()->forgetInstance(\Fissible\Vouch\Flow\AuthFlow::class);
    app()->forgetInstance(\Fissible\Vouch\Http\AuthController::class);

    expect(verificationsFor('nobody@acme.example'))->toBe(1);
});

it('verifies against a digest the ACTIVE hasher produced', function (): void {
    /*
     * The provenance proof, and the one the invocation count cannot give.
     *
     * A hard-coded bcrypt digest under an Argon-configured hasher is rejected
     * instantly, so the mitigation would return FASTER than the real path and
     * invert the leak it exists to close. Counting verifications cannot see
     * that: one check() happens either way. Identity can.
     *
     * The recorder hands back a unique sentinel from make() and records what
     * check() receives. If they match, the digest demonstrably came from the
     * active hasher.
     */
    $recorder = new RecordingHasher();

    // Swapped AFTER enrollment, so the only make() observed is the equalizer's.
    Hash::swap($recorder);
    app()->instance(Hasher::class, $recorder);
    app()->forgetInstance(\Fissible\Vouch\Flow\AuthFlow::class);
    app()->forgetInstance(\Fissible\Vouch\Http\AuthController::class);

    $session = timingSession();
    $session->start();
    $begin = timingCall([], $session);
    timingCall(['handle' => $begin['handle'], 'input' => ['identifier' => 'nobody@acme.example']], $session);
    timingCall(['handle' => $begin['handle'], 'input' => ['password' => 'wrong']], $session);

    // Identity first, deliberately. A hard-coded digest still produces exactly
    // one check(), so a count assertion firing first would mask WHY it failed;
    // this way the failure names the provenance, which is the actual claim.
    expect($recorder->checkedAgainst)->toHaveCount(1)
        ->and($recorder->made)->toContain($recorder->checkedAgainst[0])
        ->and($recorder->makeCalls)->toBe(1);
});
