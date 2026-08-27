<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Authorization\Models;

use Illuminate\Foundation\Auth\User;

/**
 * A user that reproduces spatie's grant path without spatie's schema.
 *
 * spatie's `Gate::before` hook calls `checkPermissionTo()` when the model
 * declares it (`PermissionRegistrar.php:121`), returning `true` on a held
 * permission. That truthy return is the measured fail-open in
 * `docs/authorization-integration-survey.md`: it short-circuits every hook
 * registered after it, including any Vouch could register.
 *
 * Declaring the method here drives spatie's REAL registered hook down its real
 * granting branch, which is what the end-to-end tests need to prove Vouch
 * refuses the request before that grant can happen. Running spatie's
 * migrations would prove the same thing about spatie's storage rather than
 * about Vouch's ordering.
 */
final class PermissionedProbeUser extends User
{
    protected $table = 'probe_users';

    protected $guarded = [];

    public function checkPermissionTo(mixed $ability, mixed $guard = null): bool
    {
        /** @var list<string> $held */
        $held = config()->array('vouch_test.held_permissions');

        return in_array($ability, $held, true);
    }
}
