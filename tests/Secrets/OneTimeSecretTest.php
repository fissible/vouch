<?php

declare(strict_types=1);

use Fissible\Vouch\Secrets\OneTimeSecret;
use Fissible\Vouch\Secrets\SecretAlreadyRevealed;

const PLAINTEXT = 'otpauth://totp/Acme:ada?secret=JBSWY3DPEHPK3PXP&issuer=Acme';

it('reveals the value exactly once', function (): void {
    $secret = new OneTimeSecret(PLAINTEXT);

    expect($secret->reveal())->toBe(PLAINTEXT);

    $secret->reveal();
})->throws(SecretAlreadyRevealed::class);

/*
 * Each of these is a real path by which bearer material escapes: a log line
 * interpolating the object, a queued job serialising it, an API response
 * json_encoding it, a var_dump in a debug session. None of them involves
 * anyone deciding the secret should be disclosed.
 */
it('never exposes the value through string interpolation', function (): void {
    expect((string) new OneTimeSecret(PLAINTEXT))->toBe('[redacted]')
        ->and("carrying: " . new OneTimeSecret(PLAINTEXT))->not->toContain('JBSWY3DPEHPK3PXP');
});

it('never exposes the value through json encoding', function (): void {
    $encoded = json_encode(['secret' => new OneTimeSecret(PLAINTEXT)]);

    expect($encoded)->toBe('{"secret":"[redacted]"}');
});

it('never exposes the value through php serialization', function (): void {
    expect(serialize(new OneTimeSecret(PLAINTEXT)))->not->toContain('JBSWY3DPEHPK3PXP');
});

it('never exposes the value through var_dump', function (): void {
    ob_start();
    var_dump(new OneTimeSecret(PLAINTEXT));
    $dumped = (string) ob_get_clean();

    expect($dumped)->not->toContain('JBSWY3DPEHPK3PXP');
});

it('does not survive a serialize round trip in usable form', function (): void {
    // Pins the consequence of __serialize() nulling the value: a secret that
    // reached a queue payload is dead on arrival rather than quietly usable.
    $restored = unserialize(serialize(new OneTimeSecret(PLAINTEXT)));

    expect($restored)->toBeInstanceOf(OneTimeSecret::class);

    // assert() rather than relying on the expect() above: PHPStan runs over
    // tests at level 9 and needs the narrowing before the method call below.
    assert($restored instanceof OneTimeSecret);

    $restored->reveal();
})->throws(SecretAlreadyRevealed::class);
