<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Authorization\Models;

use Illuminate\Foundation\Auth\Access\Authorizable as IlluminateAuthorizable;
use Illuminate\Foundation\Auth\User;
use Silber\Bouncer\Database\Concerns\Authorizable as BouncerAuthorizable;
use Spatie\Permission\Traits\HasRoles;

/**
 * All three packages' traits on one model, with the collision resolved
 * explicitly in favour of the Gate.
 *
 * Naming both `Authorizable` traits in the same `use` clause is what turns the
 * silent override in {@see BouncerProbeUser} into a compile-time conflict that
 * `insteadof` must settle. Keeping Illuminate's `can()` is what makes the
 * model enforceable; Bouncer's remains reachable under an alias.
 */
final class AliasedProbeUser extends User
{
    use BouncerAuthorizable, HasRoles, IlluminateAuthorizable {
        IlluminateAuthorizable::can insteadof BouncerAuthorizable;
        IlluminateAuthorizable::cant insteadof BouncerAuthorizable;
        IlluminateAuthorizable::cannot insteadof BouncerAuthorizable;
        BouncerAuthorizable::can as bouncerCan;
        BouncerAuthorizable::cant as bouncerCant;
        BouncerAuthorizable::cannot as bouncerCannot;
    }

    protected $table = 'probe_users';

    protected $guarded = [];
}
