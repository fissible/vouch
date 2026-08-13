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
