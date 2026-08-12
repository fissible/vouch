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
