<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Kernel\Policy\AllOf;
use Fissible\Vouch\Kernel\Policy\FactorRequirement;
use Fissible\Vouch\Kernel\Policy\PolicyDocument;
use Fissible\Vouch\Kernel\Policy\PolicyResolver;

function document(string $factorId, EnumerationPosture $posture = EnumerationPosture::Friendly): PolicyDocument
{
    return new PolicyDocument(
        requirement: new AllOf([new FactorRequirement($factorId)]),
        posture: $posture,
    );
}

/** Narrows the resolved requirement for PHPStan and reads its single factor id. */
function resolvedFactorId(PolicyDocument $document): string
{
    $requirement = $document->requirement;
    assert($requirement instanceof AllOf);

    $leaf = $requirement->requirements[0];
    assert($leaf instanceof FactorRequirement);

    return $leaf->factorId;
}

it('returns the only layer when just one is present', function (): void {
    $resolved = (new PolicyResolver())->resolve([document('password')]);

    expect(resolvedFactorId($resolved))->toBe('password');
});

it('prefers the most specific layer', function (): void {
    $resolved = (new PolicyResolver())->resolve([
        document('password'),   // global
        document('totp'),       // tenant
        document('passkey'),    // role
    ]);

    expect(resolvedFactorId($resolved))->toBe('passkey');
});

it('skips null layers', function (): void {
    $resolved = (new PolicyResolver())->resolve([
        document('password'),
        null,
        null,
    ]);

    expect(resolvedFactorId($resolved))->toBe('password');
});

it('takes the strictest posture across all layers, not the most specific', function (): void {
    $resolved = (new PolicyResolver())->resolve([
        document('password', EnumerationPosture::Strict),
        document('totp', EnumerationPosture::Friendly),
    ]);

    expect($resolved->posture)->toBe(EnumerationPosture::Strict);
});

it('rejects an empty layer set', function (): void {
    expect(fn () => (new PolicyResolver())->resolve([]))
        ->toThrow(InvalidArgumentException::class, 'at least one policy layer');
});

it('rejects a layer set that is entirely null', function (): void {
    expect(fn () => (new PolicyResolver())->resolve([null, null]))
        ->toThrow(InvalidArgumentException::class, 'at least one policy layer');
});
