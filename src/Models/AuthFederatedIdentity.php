<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $connection_id
 * @property string $issuer
 * @property string $subject
 * @property array<string, mixed>|null $claims
 * @property int|null $user_id
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthFederatedIdentity extends Model
{
    protected $table = 'auth_federated_identities';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['claims' => 'array'];
    }
}
