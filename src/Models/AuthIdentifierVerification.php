<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $identifier_type
 * @property string $identifier_value
 * @property string $code_hash
 * @property bool $is_decoy
 * @property Carbon $expires_at
 * @property Carbon|null $consumed_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthIdentifierVerification extends Model
{
    protected $table = 'auth_identifier_verifications';

    protected $guarded = [];

    protected function casts(): array
    {
        return ['is_decoy' => 'boolean', 'expires_at' => 'datetime', 'consumed_at' => 'datetime'];
    }
}
