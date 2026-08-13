<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Policy\AllOf;
use Fissible\Vouch\Kernel\Policy\PolicyParser;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Models\AuthTokenAssurance;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('round-trips a policy document the kernel parser accepts', function (): void {
    $document = ['all_of' => ['password', 'totp']];

    $policy = AuthPolicy::create([
        'tenant_id' => 'acme',
        'scope' => 'login',
        'document' => $document,
        'posture' => 'strict',
    ]);

    $fresh = AuthPolicy::findOrFail($policy->id);

    expect($fresh->document)->toBe($document)
        ->and($fresh->posture)->toBe('strict');

    $parsed = (new PolicyParser())->parse($fresh->document);
    expect($parsed)->toBeInstanceOf(AllOf::class);
});

it('round-trips the nested mfa preset shape through the parser', function (): void {
    // The shape parent spec §3.5 actually ships. If storage mangles nesting,
    // a policy would silently parse to something weaker than it reads.
    $document = [
        'any_of' => [
            ['all_of' => [['factor' => 'passkey', 'user_verified' => true]]],
            [
                'all_of' => ['password', 'totp'],
                'require_distinct_credentials' => true,
                'require_independent_authenticators' => true,
            ],
        ],
    ];

    $policy = AuthPolicy::create([
        'tenant_id' => 'acme',
        'scope' => 'login',
        'document' => $document,
    ]);

    $fresh = AuthPolicy::findOrFail($policy->id);

    expect($fresh->document)->toBe($document)
        ->and((new PolicyParser())->parse($fresh->document))
        ->toBeInstanceOf(\Fissible\Vouch\Kernel\Policy\AnyOf::class);
});

it('defaults the enumeration posture to friendly', function (): void {
    $policy = AuthPolicy::create([
        'tenant_id' => 'acme',
        'scope' => 'login',
        'document' => ['all_of' => ['password']],
    ]);

    expect(AuthPolicy::findOrFail($policy->id)->posture)->toBe('friendly');
});

it('allows only one policy per tenant and scope', function (): void {
    $attributes = [
        'tenant_id' => 'acme',
        'scope' => 'login',
        'document' => ['all_of' => ['password']],
    ];

    AuthPolicy::create($attributes);
    AuthPolicy::create($attributes);
})->throws(\Illuminate\Database\QueryException::class);

it('stores an amr list and credential ids as arrays', function (): void {
    $assurance = AuthTokenAssurance::create([
        'token_id' => 42,
        'acr' => 'aal2',
        'amr' => ['password', 'totp'],
        'credential_ids' => [7, 9],
        'issuing_session_id' => 'sess-1',
        'issued_at' => now(),
    ]);

    $fresh = AuthTokenAssurance::findOrFail($assurance->id);

    expect($fresh->amr)->toBe(['password', 'totp'])
        ->and($fresh->credential_ids)->toBe([7, 9])
        ->and($fresh->acr)->toBe('aal2');
});

it('allows only one assurance record per token', function (): void {
    $attributes = [
        'token_id' => 42,
        'acr' => 'aal2',
        'amr' => ['password'],
        'credential_ids' => [7],
        'issuing_session_id' => 'sess-1',
        'issued_at' => now(),
    ];

    AuthTokenAssurance::create($attributes);
    AuthTokenAssurance::create($attributes);
})->throws(\Illuminate\Database\QueryException::class);
