<?php

declare(strict_types=1);

use Fissible\Vouch\Http\AuthController;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Tests\Support\RecordingGuard;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    app()->instance(StatefulGuard::class, new RecordingGuard());

    AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['password']], 'posture' => 'strict',
    ]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'a-real-password']);
    AuthIdentifier::create(['user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now()]);
});

function retryProbeSession(): Store
{
    static $store = null;

    if ($store === null) {
        $store = new Store('retry_probe', new ArraySessionHandler(120), substr(str_repeat('retryprobesession', 3), 0, 40));
        $store->start();
    }

    return $store;
}

/**
 * @param  array<string, mixed>  $payload
 * @return array{result: string, handle: string|null, screen: array<string, mixed>}
 */
function retryProbe(array $payload): array
{
    $request = Request::create('/vouch/auth', 'POST', [], [], [], [], (string) json_encode($payload));
    $request->headers->set('Content-Type', 'application/json');
    $request->setLaravelSession(retryProbeSession());

    /** @var array{result: string, handle: string|null, screen: array<string, mixed>} $decoded */
    $decoded = json_decode((string) app(AuthController::class)($request)->getContent(), true);

    return $decoded;
}

it('returns a null retry policy for known and unknown identifiers alike', function (): void {
    /*
     * The arch scan proves no lockout is CONSTRUCTED. This proves none reaches
     * the wire, which is the property an attacker actually probes: a populated
     * retry state for a known identifier and a null one for an unknown is a
     * complete account-existence oracle, under strict posture, with every
     * kernel test green.
     */
    foreach (['ada@acme.example', 'nobody@acme.example'] as $identifier) {
        $begin = retryProbe([]);
        $identified = retryProbe(['handle' => $begin['handle'], 'input' => ['identifier' => $identifier]]);

        expect(data_get($begin, 'screen.retry'))->toBeNull()
            ->and(data_get($identified, 'screen.retry'))->toBeNull();
    }
});

it('keeps retry null through a rejected credential, for both', function (): void {
    foreach (['ada@acme.example', 'nobody@acme.example'] as $identifier) {
        $begin = retryProbe([]);
        retryProbe(['handle' => $begin['handle'], 'input' => ['identifier' => $identifier]]);
        $rejected = retryProbe(['handle' => $begin['handle'], 'input' => ['password' => 'wrong']]);

        expect(data_get($rejected, 'screen.retry'))->toBeNull();
    }
});

it('keeps retry null through repeated rejections', function (): void {
    // Repetition is what would trigger a lockout once 2.3b lands. Until the
    // precondition is satisfiable, repetition must change nothing.
    $begin = retryProbe([]);
    retryProbe(['handle' => $begin['handle'], 'input' => ['identifier' => 'ada@acme.example']]);

    foreach (range(1, 5) as $attempt) {
        expect(data_get(retryProbe(['handle' => $begin['handle'], 'input' => ['password' => 'wrong']]), 'screen.retry'))
            ->toBeNull();
    }
});
