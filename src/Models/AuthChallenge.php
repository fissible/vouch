<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $attempt_id
 * @property string $factor_type
 * @property string $code_hash
 * @property int $attempts
 * @property string|null $bound_ip
 * @property string|null $bound_user_agent
 * @property Carbon $expires_at
 * @property Carbon|null $consumed_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthChallenge extends Model
{
    protected $table = 'auth_challenges';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'attempts' => 'integer',
            'expires_at' => 'datetime',
            'consumed_at' => 'datetime',
        ];
    }
}
