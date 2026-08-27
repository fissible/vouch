<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Authorization\Models;

use Illuminate\Foundation\Auth\User;

/**
 * Admitted by spatie's ROLE branch, not its permission branch.
 *
 * `RoleOrPermissionMiddleware` refuses outright unless the model declares both
 * `hasAnyRole()` and `hasAnyPermission()`, then admits on
 * `canAny($names) || hasAnyRole($names)`. Declaring all three here lets a test
 * be admitted by the role alone, which is the case that makes the ability-name
 * collision real rather than hypothetical: Vouch sees the string `admin` on
 * the route and cannot tell that it named a role.
 */
final class RoleBearingProbeUser extends User
{
    protected $table = 'probe_users';

    protected $guarded = [];

    public function checkPermissionTo(mixed $ability, mixed $guard = null): bool
    {
        /** @var list<string> $held */
        $held = config()->array('vouch_test.held_permissions');

        return in_array($ability, $held, true);
    }

    /**
     * @param  array<int, string>|string  $roles
     */
    public function hasAnyRole($roles, mixed ...$rest): bool
    {
        /** @var list<string> $held */
        $held = config()->array('vouch_test.held_roles');

        return array_intersect(is_array($roles) ? $roles : [$roles], $held) !== [];
    }

    /**
     * Declared because spatie checks for its presence before doing anything
     * else; the role/permission decision above never consults it.
     */
    public function hasAnyPermission(mixed ...$permissions): bool
    {
        return false;
    }
}
