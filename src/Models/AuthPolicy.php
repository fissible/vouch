<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Fissible\Vouch\Models\Concerns\EnforcesValueBounds;
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
    use EnforcesValueBounds;

    protected $table = 'auth_policies';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['document' => 'array'];
    }

    /**
     * @return array<string, array{max: int, ascii?: bool}>
     */
    protected function valueBounds(): array
    {
        return [
            // Host-supplied via TenantResolver::currentTenantId(), which has no
            // length contract of its own. Bounded here because the write path
            // is the only place every writer must pass through.
            'tenant_id' => ['max' => 255],
        ];
    }
}
