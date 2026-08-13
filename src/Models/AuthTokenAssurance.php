<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $token_id
 * @property string $acr
 * @property list<string> $amr
 * @property list<int> $credential_ids
 * @property string $issuing_session_id
 * @property Carbon $issued_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthTokenAssurance extends Model
{
    protected $table = 'auth_token_assurances';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'amr' => 'array',
            'credential_ids' => 'array',
            'issued_at' => 'datetime',
        ];
    }
}
