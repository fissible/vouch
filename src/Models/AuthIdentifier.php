<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $user_id
 * @property string $type
 * @property string $value
 * @property Carbon|null $verified_at
 * @property bool $is_primary
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthIdentifier extends Model
{
    protected $table = 'auth_identifiers';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'verified_at' => 'datetime',
            'is_primary' => 'boolean',
        ];
    }
}
