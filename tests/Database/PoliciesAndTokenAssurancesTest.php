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

it('reads the stored proof back as a structure, not raw json', function (): void {
    /*
     * 2.4 Task 2 replaced this table. The old amr/credential_ids/acr columns
     * were a derived SUMMARY beside the evidence; the row now carries the
     * immutable proof itself, and the adapter reads it as a structure. Uncast,
     * it arrives as a JSON string and every structural read silently sees
     * nothing — which fails closed for every token at once and looks identical
     * to a deployment with no evidence recorded.
     */
    $assurance = AuthTokenAssurance::create([
        'issuer_key' => 'sanctum',
        'token_key' => '42',
        'subject_key' => 'App\\Models\\User:7',
        'tenant_id' => null,
        'actor_kind' => 'human',
        'acr' => 'aal2',
        'assurance_proof' => ['subject' => 'App\\Models\\User:7', 'tenant_id' => null, 'factors' => []],
        'weakest_satisfied_at' => now(),
    ]);

    $fresh = AuthTokenAssurance::findOrFail($assurance->id);

    expect($fresh->assurance_proof)->toBeArray()
        ->and($fresh->weakest_satisfied_at)->toBeInstanceOf(\Illuminate\Support\Carbon::class)
        ->and($fresh->acr)->toBe('aal2');
});

it('allows only one assurance record per issuer and token', function (): void {
    /*
     * The key is now the COMPOSITE. token_id alone stopped being unique when
     * the issuer became pluggable: two drivers can each mint id 42, and one
     * token's record would then validate the other.
     */
    $attributes = [
        'issuer_key' => 'sanctum',
        'token_key' => '42',
        'subject_key' => 'App\\Models\\User:7',
        'actor_kind' => 'human',
        'acr' => 'aal2',
        'assurance_proof' => ['subject' => 'App\\Models\\User:7', 'tenant_id' => null, 'factors' => []],
        'weakest_satisfied_at' => now(),
    ];

    AuthTokenAssurance::create($attributes);
    AuthTokenAssurance::create($attributes);
})->throws(\Illuminate\Database\QueryException::class);
