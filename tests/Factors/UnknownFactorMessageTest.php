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
