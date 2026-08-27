<?php

declare(strict_types=1);

use Fissible\Vouch\Authorization\AssuranceRequirements;

/*
 * The ability -> assurance map itself (2.3d Task 5b).
 *
 * Keys are ability NAMES, so the map works with spatie, Bouncer or plain
 * Gates and depends on none of them. Values are the assurance levels
 * AssuranceComparator already orders.
 */

it('is empty when the host has configured nothing', function (): void {
    expect(AssuranceRequirements::from([])->all())->toBe([]);
});

it('has no opinion about an ability it does not name', function (): void {
    expect(AssuranceRequirements::from(['invoices.approve' => 'aal2'])->levelFor('invoices.view'))->toBeNull();
});

it('returns the level configured for a named ability', function (): void {
    $requirements = AssuranceRequirements::from([
        'invoices.approve' => 'aal2',
        'users.impersonate' => 'aal3',
    ]);

    expect($requirements->levelFor('invoices.approve'))->toBe('aal2')
        ->and($requirements->levelFor('users.impersonate'))->toBe('aal3');
});

it('matches ability names exactly, never case-insensitively', function (): void {
    // Gate ability names are case-sensitive. A map that folded case would
    // silently apply a requirement to a DIFFERENT ability than the host wrote.
    $requirements = AssuranceRequirements::from(['invoices.approve' => 'aal2']);

    expect($requirements->levelFor('Invoices.Approve'))->toBeNull();
});

it('preserves the configured map for inspection', function (): void {
    $map = ['users.impersonate' => 'aal3', 'invoices.approve' => 'aal2'];

    expect(AssuranceRequirements::from($map)->all())->toBe($map);
});

it('refuses a configuration that is not an array', function (): void {
    expect(fn () => AssuranceRequirements::from('aal2'))
        ->toThrow(InvalidArgumentException::class, 'vouch.assurance_requirements');
});

it('refuses an unknown assurance level rather than ignoring it', function (): void {
    // Ignoring it is the failure mode this whole task exists to prevent: a
    // requirement that is configured, looks configured, and enforces nothing.
    expect(fn () => AssuranceRequirements::from(['invoices.approve' => 'aal9']))
        ->toThrow(InvalidArgumentException::class, 'invoices.approve');
});

it('names the offending value in the refusal, not just the key', function (): void {
    expect(fn () => AssuranceRequirements::from(['invoices.approve' => 'aal9']))
        ->toThrow(InvalidArgumentException::class, 'aal9');
});

it('refuses a non-string level', function (): void {
    expect(fn () => AssuranceRequirements::from(['invoices.approve' => 2]))
        ->toThrow(InvalidArgumentException::class, 'invoices.approve');
});

it('refuses an empty ability name', function (): void {
    expect(fn () => AssuranceRequirements::from(['' => 'aal2']))
        ->toThrow(InvalidArgumentException::class, 'vouch.assurance_requirements');
});

it('refuses a numeric ability key, which is a list written where a map was meant', function (): void {
    expect(fn () => AssuranceRequirements::from(['invoices.approve']))
        ->toThrow(InvalidArgumentException::class, 'vouch.assurance_requirements');
});

it('accepts every level AssuranceComparator orders', function (string $level): void {
    expect(AssuranceRequirements::from(['some.ability' => $level])->levelFor('some.ability'))->toBe($level);
})->with(['aal0', 'aal1', 'aal2', 'aal3']);

/*
 * An authorization middleware may name several abilities and grant when ANY of
 * them holds -- spatie's `permission:a|b` does exactly that. Vouch cannot see
 * which one granted, so it cannot know which requirement applies.
 */

it('has no opinion when none of the named abilities is mapped', function (): void {
    $requirements = AssuranceRequirements::from(['invoices.approve' => 'aal2']);

    expect($requirements->strongestFor(['invoices.view', 'invoices.list']))->toBeNull();
});

it('has no opinion for an empty ability list', function (): void {
    expect(AssuranceRequirements::from(['invoices.approve' => 'aal2'])->strongestFor([]))->toBeNull();
});

it('takes the STRONGEST level across an alternatives list, not the weakest', function (): void {
    /*
     * Fail closed. The authorization layer grants if ANY listed ability holds,
     * and Vouch cannot tell which one did. Taking the weakest would let a
     * request that was granted by the aal3 ability through at aal1 -- a
     * bypass created by adding a harmless-looking alternative to the route.
     */
    $requirements = AssuranceRequirements::from([
        'invoices.view' => 'aal1',
        'users.impersonate' => 'aal3',
    ]);

    expect($requirements->strongestFor(['invoices.view', 'users.impersonate']))->toBe('aal3');
});

it('ignores unmapped alternatives when computing the strongest level', function (): void {
    $requirements = AssuranceRequirements::from(['users.impersonate' => 'aal3']);

    expect($requirements->strongestFor(['invoices.view', 'users.impersonate']))->toBe('aal3');
});

it('does not depend on the order the alternatives are listed in', function (): void {
    $requirements = AssuranceRequirements::from([
        'invoices.view' => 'aal1',
        'users.impersonate' => 'aal3',
    ]);

    expect($requirements->strongestFor(['users.impersonate', 'invoices.view']))->toBe('aal3');
});

/*
 * Strict mode's check, in the one place it can be tested without booting an
 * application. 5a's bound: complete detection needs a HOST-DECLARED list,
 * because Gate::abilities() sees only explicitly define()d abilities and both
 * packages keep theirs in the database.
 */

it('accepts a map whose every ability the host declared', function (): void {
    $requirements = AssuranceRequirements::from(['invoices.approve' => 'aal2']);

    $requirements->assertDeclared(['invoices.approve', 'invoices.view']);
})->throwsNoExceptions();

it('accepts an empty map against an empty declaration', function (): void {
    AssuranceRequirements::from([])->assertDeclared([]);
})->throwsNoExceptions();

it('refuses a mapped ability the host never declared', function (): void {
    expect(fn () => AssuranceRequirements::from(['invoices.aprove' => 'aal2'])->assertDeclared(['invoices.approve']))
        ->toThrow(RuntimeException::class, 'invoices.aprove');
});

it('names every undeclared ability, not just the first', function (): void {
    $requirements = AssuranceRequirements::from([
        'invoices.aprove' => 'aal2',
        'users.impersonat' => 'aal3',
    ]);

    expect(fn () => $requirements->assertDeclared(['invoices.approve']))
        ->toThrow(RuntimeException::class, 'users.impersonat');
});

it('refuses a non-empty map against an empty declaration', function (): void {
    // Asking for strict mode while declaring nothing cannot be satisfied, and
    // silently passing would make strict mode a no-op that reads as enabled.
    expect(fn () => AssuranceRequirements::from(['invoices.approve' => 'aal2'])->assertDeclared([]))
        ->toThrow(RuntimeException::class, 'vouch.declared_abilities');
});

/*
 * The declared-ability list is strict mode's ONLY source, so a malformed one
 * must be refused rather than silently narrowed. A list that quietly becomes
 * empty turns strict mode into a boot failure for a correct map; one that
 * quietly accepts junk lets a typo through the check that exists to catch it.
 */

it('reads a list of declared abilities', function (): void {
    expect(AssuranceRequirements::declaredFrom(['invoices.approve', 'invoices.view']))
        ->toBe(['invoices.approve', 'invoices.view']);
});

it('reads an empty declaration', function (): void {
    expect(AssuranceRequirements::declaredFrom([]))->toBe([]);
});

it('refuses a declaration that is not an array', function (): void {
    expect(fn () => AssuranceRequirements::declaredFrom('invoices.approve'))
        ->toThrow(InvalidArgumentException::class, 'vouch.declared_abilities');
});

it('refuses a non-string entry in the declaration', function (): void {
    expect(fn () => AssuranceRequirements::declaredFrom(['invoices.approve', 42]))
        ->toThrow(InvalidArgumentException::class, 'vouch.declared_abilities');
});

it('refuses an empty string in the declaration', function (): void {
    // An empty entry matches no ability and would silently pad the list,
    // making a short declaration look longer than it is.
    expect(fn () => AssuranceRequirements::declaredFrom(['invoices.approve', '']))
        ->toThrow(InvalidArgumentException::class, 'vouch.declared_abilities');
});

it('refuses a map written where a list of declarations was meant', function (): void {
    expect(fn () => AssuranceRequirements::declaredFrom(['invoices.approve' => 'aal2']))
        ->toThrow(InvalidArgumentException::class, 'vouch.declared_abilities');
});

it('matches declarations exactly, never by loose comparison', function (): void {
    /*
     * Both values are numeric strings, so PHP compares them NUMERICALLY under
     * `==`: '0e123' == '0' is true. A loose `in_array()` would therefore
     * accept the declaration as covering the mapped ability, and strict mode
     * would vouch for a key nobody declared. Comparing two obviously
     * different names would pass under either comparison and prove nothing.
     */
    expect(fn () => AssuranceRequirements::from(['0e123' => 'aal2'])->assertDeclared(['0']))
        ->toThrow(RuntimeException::class, '0e123');
});

it('accepts a declaration that matches the mapped ability exactly', function (): void {
    // The other half of the pair above: strict matching must still MATCH.
    AssuranceRequirements::from(['0e123' => 'aal2'])->assertDeclared(['0e123']);
})->throwsNoExceptions();

it('refuses a whitespace-only ability name', function (): void {
    /*
     * The scanner trims ability names out of middleware parameters, so a
     * whitespace-only key can never match a route. Accepting it lets a map
     * entry and a matching declaration satisfy strict mode while protecting
     * nothing -- a requirement that is configured, passes validation, and is
     * unreachable.
     */
    expect(fn () => AssuranceRequirements::from(['   ' => 'aal2']))
        ->toThrow(InvalidArgumentException::class, 'vouch.assurance_requirements');
});

it('refuses a whitespace-only declaration', function (): void {
    expect(fn () => AssuranceRequirements::declaredFrom(['invoices.approve', '   ']))
        ->toThrow(InvalidArgumentException::class, 'vouch.declared_abilities');
});

it('refuses an ability name with surrounding whitespace', function (): void {
    /*
     * ' invoices.approve ' validates against a declaration written the same
     * way, so strict mode reports the map as sound -- and then never fires,
     * because the scanner trims `permission: invoices.approve ` down to the
     * unpadded name and finds no map entry for it. The requirement is
     * configured, verified, and unreachable, which is the exact silent
     * disable this task exists to prevent. Names must be canonical, not
     * merely non-empty.
     */
    expect(fn () => AssuranceRequirements::from([' invoices.approve ' => 'aal2']))
        ->toThrow(InvalidArgumentException::class, 'vouch.assurance_requirements');
});

it('refuses a declared ability with surrounding whitespace', function (): void {
    expect(fn () => AssuranceRequirements::declaredFrom([' invoices.approve ']))
        ->toThrow(InvalidArgumentException::class, 'vouch.declared_abilities');
});

it('refuses a trailing newline in an ability name, not just spaces', function (): void {
    expect(fn () => AssuranceRequirements::from(["invoices.approve\n" => 'aal2']))
        ->toThrow(InvalidArgumentException::class, 'vouch.assurance_requirements');
});

it('still accepts a canonical ability name that contains no whitespace', function (): void {
    // The pair for the three above: canonicalisation must reject padding
    // without rejecting ordinary names.
    expect(AssuranceRequirements::from(['invoices.approve' => 'aal2'])->levelFor('invoices.approve'))
        ->toBe('aal2');
});

it('refuses a trailing newline in a declared ability too', function (): void {
    // The map parser and the declaration parser are separate seams; proving
    // spaces on one and newlines on the other leaves a split implementation
    // that admits newline-padded declarations.
    expect(fn () => AssuranceRequirements::declaredFrom(["invoices.approve\n"]))
        ->toThrow(InvalidArgumentException::class, 'vouch.declared_abilities');
});
