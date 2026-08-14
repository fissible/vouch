<?php

declare(strict_types=1);

use Fissible\Vouch\Secrets\OneTimeSecret;

/*
 * OneTimeSecret exists to stop a plaintext secret reaching a log, a crash
 * report, an API response or a debugger. Every one of those is a different
 * escape route with a different magic method behind it, so each is asserted
 * separately -- a secret that is redacted in three of the four is not redacted.
 *
 * These survivors were sitting in a namespace at 27% and would have read as
 * cosmetic string handling.
 */

const SECRET_PLAINTEXT = 'correct horse battery staple';

it('reveals the value to a caller that asks for it', function (): void {
    // The one intended exit. Without it the class is merely a black hole.
    expect((new OneTimeSecret(SECRET_PLAINTEXT))->reveal())->toBe(SECRET_PLAINTEXT);
});

it('never leaks through any accidental exit', function (string $route): void {
    /*
     * Each of these is reached WITHOUT anyone deciding to reveal the secret:
     *
     * - string interpolation is how a value lands in a log line.
     * - json_encode is how it lands in an API response.
     * - print_r/var_export are how it lands in a crash report or a dump.
     *
     * The assertion is on the rendered output, not on the method, because what
     * matters is what the escape route actually emits.
     */
    $secret = new OneTimeSecret(SECRET_PLAINTEXT);

    $rendered = match ($route) {
        'interpolation' => "value: {$secret}",
        'cast' => (string) $secret,
        'json' => (string) json_encode($secret),
        'print_r' => print_r($secret, true),
        'var_export' => var_export($secret, true),
        default => throw new InvalidArgumentException($route),
    };

    expect($rendered)->not->toContain(SECRET_PLAINTEXT)
        ->and($rendered)->toContain('[redacted]');
})->with(['interpolation', 'cast', 'json', 'print_r']);

it('redacts under var_dump, which reads __debugInfo rather than the properties', function (): void {
    /*
     * The route the other cases miss. var_dump() consults __debugInfo() and
     * nothing else, so a class redacted for logs and JSON can still print its
     * plaintext into a debugger session or an xdebug trace.
     *
     * Asserted on captured output, and asserted BOTH ways: the plaintext absent
     * and the marker present. Absence alone would be satisfied by __debugInfo()
     * returning an empty array, which hides the secret but also hides that there
     * is a secret -- and a dump that shows nothing invites someone to reach for
     * reveal() to see what is in there.
     */
    ob_start();
    var_dump(new OneTimeSecret(SECRET_PLAINTEXT));
    $dumped = (string) ob_get_clean();

    expect($dumped)->not->toContain(SECRET_PLAINTEXT)
        ->and($dumped)->toContain('[redacted]')
        ->and($dumped)->toContain('value');
});

it('keeps the plaintext out of serialize()', function (): void {
    // Already guarded: the serialized form carries a null where the value would
    // be, so a session payload or cache entry cannot carry the secret.
    expect(serialize(new OneTimeSecret(SECRET_PLAINTEXT)))->not->toContain(SECRET_PLAINTEXT);
});

it('keeps the plaintext out of var_export()', function (): void {
    /*
     * The route that made every other redaction moot. var_export() reads an
     * object's raw instance properties and consults neither __debugInfo() nor
     * __toString() nor jsonSerialize(), so a redacting property-holder leaked in
     * full -- and var_export() is what writes cached config and what several dump
     * helpers and debug toolbars call.
     *
     * Closed by moving the value off the object entirely, into a WeakMap keyed by
     * the instance. There is no property left to read.
     *
     * Asserted for the plaintext AND for any alternate recoverable value: the
     * exported state must be empty, not merely free of this particular string.
     */
    $exported = var_export(new OneTimeSecret(SECRET_PLAINTEXT), true);

    expect($exported)->not->toContain(SECRET_PLAINTEXT)
        ->and($exported)->not->toContain('correct horse')
        // An empty state array -- nothing exported that could be recovered.
        ->and(preg_replace('/\s+/', '', $exported))
        ->toBe("\\Fissible\\Vouch\\Secrets\\OneTimeSecret::__set_state(array())");
});

it('cannot be rebuilt into a usable secret from exported state', function (): void {
    // Evaluating var_export() output must not manufacture a second secret. It
    // cannot -- no state is exported -- so the refusal is explicit rather than a
    // hollow instance that looks like a secret and reveals nothing.
    expect(fn (): OneTimeSecret => OneTimeSecret::__set_state(['value' => SECRET_PLAINTEXT]))
        ->toThrow(LogicException::class);
});

it('cannot be cloned into a second usable secret', function (): void {
    /*
     * A clone is a distinct object with no map entry of its own. Silently it
     * would be an unusable look-alike -- easy to mistake for a copy of the
     * secret, and easy to pass on in place of the original. Refusing says so at
     * the point of the mistake.
     */
    $secret = new OneTimeSecret(SECRET_PLAINTEXT);

    expect(static fn (): OneTimeSecret => clone $secret)->toThrow(LogicException::class)
        // And the original is untouched by the attempt.
        ->and($secret->reveal())->toBe(SECRET_PLAINTEXT);
});

it('still reveals once, and only once, for the original instance', function (): void {
    // The behaviour the move must not change: one read, then spent.
    $secret = new OneTimeSecret(SECRET_PLAINTEXT);

    expect($secret->reveal())->toBe(SECRET_PLAINTEXT)
        ->and(fn (): string => $secret->reveal())
        ->toThrow(\Fissible\Vouch\Secrets\SecretAlreadyRevealed::class);
});

it('keeps distinct instances independent', function (): void {
    // A WeakMap keyed by instance must not let one secret answer for another.
    $a = new OneTimeSecret('alpha');
    $b = new OneTimeSecret('beta');

    expect($b->reveal())->toBe('beta')
        ->and($a->reveal())->toBe('alpha');
});
