<?php

declare(strict_types=1);

use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Factors\UnknownFactor;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * These look like message-text assertions and they are not, which is why they
 * sit here rather than being deferred with the rest of the copy.
 *
 * UnknownFactor is thrown when a policy names a driver the registry does not
 * have. Two very different faults produce it: a misspelled or unregistered
 * factor id, and a registry that was never populated at all -- typically a
 * service provider that did not boot. The message is the only thing that
 * separates them, and the branch that does the separating is a live conditional,
 * not prose.
 *
 * The list of registered ids is a diagnostic payload rather than decoration:
 * without it, "no driver for totp" gives the operator nothing to compare
 * against.
 */

it('reports an empty registry differently from a missing driver', function (): void {
    /*
     * `$known === [] ? 'none' : implode(...)` -- with the comparison or the
     * ternary inverted, an empty registry reports the ids it does not have and a
     * populated one reports "none". Both readings are plausible-looking output,
     * and each sends the operator to the wrong bug.
     */
    $empty = new FactorRegistry();

    expect(fn (): mixed => $empty->get('totp'))
        ->toThrow(UnknownFactor::class, 'No factor driver is registered for "totp". Registered: none.');
});

it('names the drivers it does have', function (): void {
    /*
     * Also the only thing standing behind array_keys(): unwrapped, the message
     * would try to render the driver OBJECTS, and the diagnostic would become an
     * "object could not be converted to string" error thrown from inside the
     * error path.
     */
    $registry = new FactorRegistry();
    $registry->register(app(PasswordFactor::class));

    expect(fn (): mixed => $registry->get('totp'))
        ->toThrow(UnknownFactor::class, 'No factor driver is registered for "totp". Registered: password.');
});

it('refuses to replace a driver that is already registered', function (): void {
    /*
     * Write-once registration, and the reason it is write-once is a security
     * one: the registry is what maps a credential type to the driver that owns
     * it, and silent replacement would let a permissive implementation displace a
     * restrictive one simply by registering afterwards. The recovery-code driver
     * is the sharpest case -- it carries FactorStrength::Recovery, which is what
     * stops a printed code satisfying a login policy.
     *
     * The refusal was described by an exception message that nothing asserted;
     * this asserts the behaviour the message describes.
     */
    $registry = new FactorRegistry();
    $registry->register(app(PasswordFactor::class));

    /*
     * 'already registered' is prose and says nothing about WHICH key collided.
     * The identity artifacts are the two sprintf arguments — the factor id, and
     * the class already holding it — and they are what makes the refusal
     * actionable when a host registers a driver over one of the shipped five.
     * Asserting them also pins their ORDER, which positional %s substitution
     * would otherwise let drift.
     */
    expect(function () use ($registry): void { $registry->register(app(PasswordFactor::class)); })
        ->toThrow(LogicException::class, 'already registered for "password" (' . PasswordFactor::class . ')');
});

it('keeps the first driver when a replacement is refused', function (): void {
    /*
     * The refusal must leave the original in place. A registry that threw AFTER
     * overwriting would report the violation and still be compromised -- the
     * error would look like the control working while the permissive driver was
     * already installed.
     */
    $registry = new FactorRegistry();
    $first = app(PasswordFactor::class);
    $registry->register($first);

    try {
        $registry->register(app(PasswordFactor::class));
    } catch (LogicException) {
        // expected
    }

    expect($registry->get('password'))->toBe($first);
});
