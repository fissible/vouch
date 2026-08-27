<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Authorization\Models;

use Illuminate\Foundation\Auth\User;
use Silber\Bouncer\Database\Concerns\Authorizable as BouncerAuthorizable;

/**
 * Bouncer's trait applied the way its own README shows.
 *
 * This does NOT raise a collision even though the parent class already uses
 * Illuminate's `Authorizable`: a trait method used in the class takes
 * precedence over an inherited method. The override is therefore silent, and
 * `can()` stops reaching the Gate with no compile-time signal.
 */
final class BouncerProbeUser extends User
{
    use BouncerAuthorizable;

    protected $table = 'probe_users';

    protected $guarded = [];
}
