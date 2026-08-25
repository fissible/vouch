<?php

declare(strict_types=1);

use Fissible\Vouch\Http\IntendedDestination;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;

uses(RefreshDatabase::class);

function destination(): IntendedDestination
{
    $store = new Store('dest', new ArraySessionHandler(120), substr(str_repeat('destinationsession', 3), 0, 40));
    $store->start();

    return new IntendedDestination($store);
}

it('round-trips a safe same-origin path with its query', function (): void {
    $destination = destination();
    $destination->remember('/admin/settings?tab=security');

    expect($destination->consume())->toBe('/admin/settings?tab=security');
});

it('clears the target once consumed', function (): void {
    // A stored destination that survives consumption can be replayed by a later
    // step-up to send a user somewhere they never asked to go.
    $destination = destination();
    $destination->remember('/admin/settings');
    $destination->consume();

    expect($destination->consume())->toBeNull();
});

it('discards every off-origin form', function (string $hostile): void {
    /*
     * Discarded, not sanitised. Sanitising a hostile value is how the encoded
     * and normalised authority cases survive: strip one prefix and the next
     * layer reconstitutes it.
     */
    $destination = destination();
    $destination->remember($hostile);

    expect($destination->consume())->toBeNull();
})->with([
    'protocol-relative' => '//evil.example/path',
    'protocol-relative, triple' => '///evil.example',
    'absolute https' => 'https://evil.example/path',
    'absolute http' => 'http://evil.example',
    'scheme-only' => 'javascript:alert(1)',
    'data uri' => 'data:text/html,<script>alert(1)</script>',
    'backslash authority' => '/\evil.example',
    'double backslash' => '\\\\evil.example',
    'encoded slash authority' => '/%2f%2fevil.example',
    'encoded slash authority, upper' => '/%2F%2Fevil.example',
    'encoded backslash' => '/%5cevil.example',
    'encoded backslash, upper' => '/%5Cevil.example',
    'relative, no leading slash' => 'admin/settings',
    'empty' => '',
]);

it('keeps a query string containing an encoded slash in a value', function (): void {
    /*
     * The rejection is about the AUTHORITY position, not about %2f appearing
     * anywhere. Over-rejecting would break legitimate redirect targets and
     * train someone to loosen the rule -- which is how the real hole gets
     * opened later.
     */
    $destination = destination();
    $destination->remember('/search?q=a%2Fb');

    expect($destination->consume())->toBe('/search?q=a%2Fb');
});

it('discards a hostile value rather than leaving a previous one in place', function (): void {
    // Otherwise a hostile submission would silently inherit whatever target was
    // stored before it.
    $destination = destination();
    $destination->remember('/admin/settings');
    $destination->remember('//evil.example');

    expect($destination->consume())->toBeNull();
});

it('rejects malformed and authority-shaped origin candidates after parsing', function (string $candidate): void {
    $destination = destination();
    $destination->remember($candidate);

    expect($destination->consume())->toBeNull();
})->with([
    'malformed port' => '/not-a-host:80',
    'authority-shaped path' => '//user:pass@host/path',
    'missing origin slash' => 'user:pass@host/path',
]);
