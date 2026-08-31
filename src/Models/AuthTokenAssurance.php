<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Fissible\Vouch\Models\Casts\UtcDateTime;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $issuer_key
 * @property string $token_key
 * @property string $subject_key
 * @property string|null $tenant_id
 * @property string $actor_kind
 * @property string|null $acr
 * @property array<string,mixed>|null $assurance_proof
 * @property Carbon|null $weakest_satisfied_at
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
            'assurance_proof' => 'array',
            'weakest_satisfied_at' => UtcDateTime::class,
        ];
    }
}
