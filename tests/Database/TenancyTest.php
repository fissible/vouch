<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\TenantResolver;
use Fissible\Vouch\Tenancy\NullTenantResolver;

it('resolves the null tenant resolver by default', function (): void {
    expect(app(TenantResolver::class))->toBeInstanceOf(NullTenantResolver::class);
});

it('reports no tenant in a single-tenant application', function (): void {
    expect(app(TenantResolver::class)->currentTenantId())->toBeNull();
});

it('leaves AuditSink unbound so audit events cannot silently vanish', function (): void {
    // Drivers ship in 2.4. Until then resolving this must fail loudly: a
    // silently-bound no-op would discard security events while looking healthy.
    app(\Fissible\Vouch\Contracts\AuditSink::class);
})->throws(\Illuminate\Contracts\Container\BindingResolutionException::class);
