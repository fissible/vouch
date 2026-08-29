<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Tokens;

use Illuminate\Foundation\Auth\User;

/**
 * A subject WITHOUT HasApiTokens. Sanctum's guard refuses to attach an access
 * token to one, so neither a session principal of this type nor a token whose
 * tokenable is of this type may be claimed.
 */
final class PlainUser extends User
{
    protected $table = 'plain_users';

    protected $guarded = [];
}
