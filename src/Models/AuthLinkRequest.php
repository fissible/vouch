<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $user_id
 * @property int $federated_identity_id
 * @property Carbon|null $proven_at
 * @property Carbon $expires_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthLinkRequest extends Model
{
    protected $table = 'auth_link_requests';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'proven_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }
}
