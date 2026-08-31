<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Tenancy;

use Fissible\Vouch\Contracts\TenantResolver;

/**
 * A host tenancy seam with a known answer.
 *
 * Named rather than anonymous so the nullable return is genuinely nullable:
 * a resolver that deliberately reports "no tenant" is the single-tenant case
 * Vouch must keep working, and it is exactly what an ambient config scalar
 * could never express.
 */
final readonly class FixedTenantResolver implements TenantResolver
{
    public function __construct(private ?string $tenantId) {}

    public function currentTenantId(): ?string
    {
        return $this->tenantId;
    }
}
