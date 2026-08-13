<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

/**
 * Resolves the tenant for the current request.
 *
 * Vouch never references a host application's tenant model. Station binds an
 * adapter over its own TenantContext; single-tenant hosts use NullTenantResolver.
 */
interface TenantResolver
{
    /**
     * The current tenant's identifier, or null in a single-tenant application.
     */
    public function currentTenantId(): ?string;
}
