<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Fissible\Vouch\Models\Concerns\EnforcesValueBounds;
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
    use EnforcesValueBounds;

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

    /**
     * @return array<string, array{max: int, ascii?: bool}>
     */
    protected function valueBounds(): array
    {
        return [
            // Registration input, and half of the unique (type, value) index.
            // Same input-boundary class as the federated-identity columns.
            'value' => ['max' => 255],
        ];
    }
}
