<?php

declare(strict_types=1);

use Fissible\Vouch\Http\AuthController;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Tests\Support\RecordingGuard;
use Fissible\Vouch\Tests\Support\ReferenceRenderer;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;

uses(RefreshDatabase::class);

function rendererSession(): Store
{
    static $store = null;

    if ($store === null) {
        $store = new Store('renderer', new ArraySessionHandler(120), substr(str_repeat('renderersession', 3), 0, 40));
        $store->start();
    }

    return $store;
}

/**
 * @param  array<string, mixed>  $payload
 * @return array{result: string, handle: string|null, screen: array<string, mixed>}
 */
function rendererCall(array $payload): array
{
    $request = Request::create('/vouch/auth', 'POST', [], [], [], [], (string) json_encode($payload));
    $request->headers->set('Content-Type', 'application/json');
    $request->setLaravelSession(rendererSession());

    /** @var array{result: string, handle: string|null, screen: array<string, mixed>} $decoded */
    $decoded = json_decode((string) app(AuthController::class)($request)->getContent(), true);

    return $decoded;
}

/**
 * @param  array{result: string, handle: string|null, screen: array<string, mixed>}  $envelope
 */
function renderScreen(array $envelope): string
{
    return (new ReferenceRenderer())->render($envelope);
}

beforeEach(function (): void {
    app()->instance(StatefulGuard::class, new RecordingGuard());

    AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['password']], 'posture' => 'friendly',
    ]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'a-real-password']);
    AuthIdentifier::create(['user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now()]);
});

it('renders the identify screen through the real endpoint', function (): void {
    $html = renderScreen(rendererCall([]));

    expect($html)->toContain('data-step="identify"')
        ->and($html)->toContain('name="identifier"')
        ->and($html)->toContain('autocomplete="username"');
});

it('renders the challenge screen with its offered factors', function (): void {
    $begin = rendererCall([]);
    $html = renderScreen(rendererCall(['handle' => $begin['handle'], 'input' => ['identifier' => 'ada@acme.example']]));

    expect($html)->toContain('data-step="challenge"')
        ->and($html)->toContain('data-factor="password"')
        ->and($html)->toContain('data-default="1"');
});

it('renders a shaped error screen', function (): void {
    $begin = rendererCall([]);
    rendererCall(['handle' => $begin['handle'], 'input' => ['identifier' => 'ada@acme.example']]);
    $html = renderScreen(rendererCall(['handle' => $begin['handle'], 'input' => ['password' => 'wrong']]));

    expect($html)->toContain('vouch-errors')
        ->and($html)->toContain('<li>');
});

it('renders no retry block, because 2.3 never emits one', function (): void {
    expect(renderScreen(rendererCall([])))->not->toContain('vouch-retry');
});

it('never echoes the submitted identifier back into the screen at all', function (): void {
    /*
     * Not an escaping test -- a contract test, and the distinction matters.
     *
     * An earlier version asserted the rendered HTML did not contain a hostile
     * identifier and passed for the wrong reason: ScreenSpec never carries
     * submitted input back, so the value was ABSENT rather than escaped. That
     * assertion would have held against a renderer with no escaping whatsoever.
     *
     * The real property is that the flow does not echo submitted input, which
     * is why it cannot become an injection vector here. Asserted on the
     * envelope, where it is actually decidable.
     */
    $begin = rendererCall([]);
    $envelope = rendererCall([
        'handle' => $begin['handle'],
        'input' => ['identifier' => '<script>alert(1)</script>'],
    ]);

    expect(json_encode($envelope))->not->toContain('script')
        ->and(renderScreen($envelope))->not->toContain('<script>');
});

it('escapes hostile content reaching the error list', function (): void {
    $begin = rendererCall([]);
    $envelope = rendererCall(['handle' => $begin['handle'], 'input' => ['identifier' => 'nobody@acme.example']]);
    $envelope['screen']['errors'] = ['<img src=x onerror="alert(1)">'];

    $html = renderScreen($envelope);

    expect($html)->not->toContain('<img src=x')
        ->and($html)->toContain('&lt;img');
});

it('is not registered anywhere in production source', function (): void {
    // The renderer is a test consumer, not an adapter. If src/ ever references
    // it, vouch has grown a UI story it deliberately does not own.
    $hits = [];

    /** @var iterable<SplFileInfo> $files */
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__ . '/../../src'));

    foreach ($files as $file) {
        if ($file->isFile() && $file->getExtension() === 'php'
            && str_contains((string) file_get_contents($file->getPathname()), 'ReferenceRenderer')) {
            $hits[] = $file->getPathname();
        }
    }

    expect($hits)->toBeEmpty();
});
