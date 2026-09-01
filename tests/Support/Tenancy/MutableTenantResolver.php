<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Tenancy;

use Fissible\Vouch\Contracts\TenantResolver;

/**
 * A tenancy seam whose answer CHANGES between calls.
 *
 * The contract is that the tenant is CARRIED from the attempt, not re-derived
 * later. A resolver fixed for the whole test cannot tell those apart: an
 * implementation that asked the resolver again at session-write time would
 * agree with one that carried the value, and every fixed-resolver test would
 * pass either way.
 *
 * Changing the answer after the attempt is stamped separates them.
 */
final class MutableTenantResolver implements TenantResolver
{
    public function __construct(public ?string $tenantId) {}

    public function currentTenantId(): ?string
    {
        return $this->tenantId;
    }
}
