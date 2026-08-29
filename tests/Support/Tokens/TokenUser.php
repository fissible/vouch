<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Tokens;

use Illuminate\Foundation\Auth\User;
use Laravel\Sanctum\HasApiTokens;

/**
 * A tokenable subject. Sanctum's guard refuses any model that does not use
 * HasApiTokens (`Guard::supportsTokens()`), so the trait is the thing under
 * test here, not decoration.
 */
final class TokenUser extends User
{
    use HasApiTokens;

    protected $table = 'token_users';

    protected $guarded = [];
}
