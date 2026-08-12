<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Policy\AllOf;
use Fissible\Vouch\Kernel\Policy\AnyOf;
use Fissible\Vouch\Kernel\Policy\FactorRequirement;
use Fissible\Vouch\Kernel\Policy\PolicyParser;

it('parses a bare factor name into a leaf requirement', function (): void {
    $parsed = (new PolicyParser())->parse(['all_of' => ['password']]);

    // assert() rather than expect()->toBeInstanceOf(): PHPStan runs over tests at
    // level 9 and needs the narrowing before the property accesses below.
    assert($parsed instanceof AllOf);
    $leaf = $parsed->requirements[0];
    assert($leaf instanceof FactorRequirement);

    expect($parsed->requirements)->toHaveCount(1)
        ->and($leaf->factorId)->toBe('password');
});

it('parses leaf constraints', function (): void {
    $parsed = (new PolicyParser())->parse([
        'all_of' => [
            ['factor' => 'passkey', 'user_verified' => true, 'minimum_strength' => 'possession'],
        ],
    ]);

    assert($parsed instanceof AllOf);
    $leaf = $parsed->requirements[0];
    assert($leaf instanceof FactorRequirement);

    expect($leaf->factorId)->toBe('passkey')
        ->and($leaf->userVerified)->toBeTrue()
        ->and($leaf->minimumStrength)->toBe(FactorStrength::Possession);
});

it('defaults distinct credentials to required and independence to not required', function (): void {
    $parsed = (new PolicyParser())->parse(['all_of' => ['password', 'totp']]);

    assert($parsed instanceof AllOf);

    expect($parsed->requireDistinctCredentials)->toBeTrue()
        ->and($parsed->requireIndependentAuthenticators)->toBeFalse();
});

it('parses the mfa preset shape', function (): void {
    $parsed = (new PolicyParser())->parse([
        'any_of' => [
            ['all_of' => [['factor' => 'passkey', 'user_verified' => true]]],
            [
                'all_of' => ['password', 'totp'],
                'require_distinct_credentials' => true,
                'require_independent_authenticators' => true,
            ],
        ],
    ]);

    assert($parsed instanceof AnyOf);
    $second = $parsed->requirements[1];
    assert($second instanceof AllOf);

    expect($parsed->requirements)->toHaveCount(2)
        ->and($second->requireIndependentAuthenticators)->toBeTrue();
});

it('rejects a node that is neither all_of nor any_of', function (): void {
    expect(fn () => (new PolicyParser())->parse(['some_of' => ['password']]))
        ->toThrow(InvalidArgumentException::class, 'must declare exactly one of');
});

it('rejects an empty branch', function (): void {
    expect(fn () => (new PolicyParser())->parse(['all_of' => []]))
        ->toThrow(InvalidArgumentException::class, 'must not be empty');
});

it('rejects an unknown strength name', function (): void {
    expect(fn () => (new PolicyParser())->parse([
        'all_of' => [['factor' => 'password', 'minimum_strength' => 'extremely']],
    ]))->toThrow(InvalidArgumentException::class, 'unknown minimum_strength');
});

it('rejects a node declaring both all_of and any_of', function (): void {
    expect(fn () => (new PolicyParser())->parse([
        'all_of' => ['password'],
        'any_of' => ['totp'],
    ]))->toThrow(InvalidArgumentException::class, 'must declare exactly one of');
});

it('rejects a child that is neither a string nor an array', function (): void {
    expect(fn () => (new PolicyParser())->parse(['all_of' => [42]]))
        ->toThrow(InvalidArgumentException::class, 'must be a factor name or an array');
});

it('rejects a leaf array missing the factor key', function (): void {
    expect(fn () => (new PolicyParser())->parse(['all_of' => [['user_verified' => true]]]))
        ->toThrow(InvalidArgumentException::class, 'must declare a string factor');
});

it('rejects a leaf whose factor is not a string', function (): void {
    expect(fn () => (new PolicyParser())->parse(['all_of' => [['factor' => 42]]]))
        ->toThrow(InvalidArgumentException::class, 'must declare a string factor');
});

it('rejects a non-string minimum_strength', function (): void {
    expect(fn () => (new PolicyParser())->parse([
        'all_of' => [['factor' => 'password', 'minimum_strength' => 5]],
    ]))->toThrow(InvalidArgumentException::class, 'unknown minimum_strength');
});

it('rejects a non-boolean require_distinct_credentials', function (string|int $value): void {
    expect(fn () => (new PolicyParser())->parse([
        'all_of' => ['password'],
        'require_distinct_credentials' => $value,
    ]))->toThrow(InvalidArgumentException::class, 'require_distinct_credentials must be a boolean');
})->with([
    'empty string' => [''],
    'string zero' => ['0'],
    'string false' => ['false'],
    'int zero' => [0],
]);

it('honours an explicit boolean require_distinct_credentials', function (): void {
    $parsed = (new PolicyParser())->parse([
        'all_of' => ['password'],
        'require_distinct_credentials' => false,
    ]);

    assert($parsed instanceof AllOf);

    expect($parsed->requireDistinctCredentials)->toBeFalse();
});

it('defaults require_distinct_credentials to true when absent or explicitly null', function (): void {
    $absent = (new PolicyParser())->parse(['all_of' => ['password']]);
    assert($absent instanceof AllOf);

    $explicitNull = (new PolicyParser())->parse([
        'all_of' => ['password'],
        'require_distinct_credentials' => null,
    ]);
    assert($explicitNull instanceof AllOf);

    expect($absent->requireDistinctCredentials)->toBeTrue()
        ->and($explicitNull->requireDistinctCredentials)->toBeTrue();
});

it('rejects a non-boolean require_independent_authenticators', function (): void {
    expect(fn () => (new PolicyParser())->parse([
        'all_of' => ['password'],
        'require_independent_authenticators' => '',
    ]))->toThrow(InvalidArgumentException::class, 'require_independent_authenticators must be a boolean');
});

it('defaults require_independent_authenticators to false when absent', function (): void {
    $parsed = (new PolicyParser())->parse(['all_of' => ['password']]);
    assert($parsed instanceof AllOf);

    expect($parsed->requireIndependentAuthenticators)->toBeFalse();
});
