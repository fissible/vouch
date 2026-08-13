<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $handle
 * @property AttemptState $state
 * @property int $version
 * @property string|null $tenant_id
 * @property string|null $identifier
 * @property int|null $user_id
 * @property string|null $bound_context
 * @property list<array<string, mixed>>|null $satisfied_factors
 * @property Carbon $expires_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthAttempt extends Model
{
    protected $table = 'auth_attempts';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'state' => AttemptState::class,
            'version' => 'integer',
            'satisfied_factors' => 'array',
            'expires_at' => 'datetime',
        ];
    }

    /**
     * @return HasMany<AuthChallenge, $this>
     */
    public function challenges(): HasMany
    {
        return $this->hasMany(AuthChallenge::class, 'attempt_id');
    }
}
