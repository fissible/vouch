<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string|null $tenant_id
 * @property string $scope
 * @property array<string, mixed> $document
 * @property string $posture
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthPolicy extends Model
{
    protected $table = 'auth_policies';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['document' => 'array'];
    }
}
