<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Authorization\Models;

use Illuminate\Foundation\Auth\User;

/**
 * A stock Laravel user: `Illuminate\Foundation\Auth\User` already uses
 * `Illuminate\Foundation\Auth\Access\Authorizable`, which delegates `can()`
 * to the Gate.
 */
final class PlainProbeUser extends User
{
    protected $table = 'probe_users';

    protected $guarded = [];
}
