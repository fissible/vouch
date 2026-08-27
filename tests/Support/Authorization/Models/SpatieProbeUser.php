<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Authorization\Models;

use Illuminate\Foundation\Auth\User;
use Spatie\Permission\Traits\HasRoles;

/**
 * spatie's `HasRoles` adds `hasPermissionTo()` and `checkPermissionTo()`; it
 * does NOT override `can()`, so the inherited Gate delegation survives.
 */
final class SpatieProbeUser extends User
{
    use HasRoles;

    protected $table = 'probe_users';

    protected $guarded = [];
}
