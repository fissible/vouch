<?php

declare(strict_types=1);

namespace Vendor\Probe;

/** A real issuance site a host has reviewed and accepted. */
final class AllowlistedIssuer
{
    public function mint(User $user): string
    {
        return $user->createToken('service')->plainTextToken;
    }
}
