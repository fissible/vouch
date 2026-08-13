<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tenancy;

use Fissible\Vouch\Contracts\TenantResolver;

final class NullTenantResolver implements TenantResolver
{
    public function currentTenantId(): ?string
    {
        return null;
    }
}
