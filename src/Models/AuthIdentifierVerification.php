<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Fissible\Vouch\Models\Concerns\EnforcesValueBounds;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $identifier_type
 * @property string $identifier_value
 * @property string $code_hash
 * @property bool $is_decoy
 * @property int $attempts
 * @property Carbon|null $burned_at
 * @property Carbon $expires_at
 * @property Carbon|null $consumed_at
 * @property Carbon|null $superseded_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthIdentifierVerification extends Model
{
    use EnforcesValueBounds;

    protected $table = 'auth_identifier_verifications';

    protected $guarded = [];

    protected function casts(): array
    {
        return ['is_decoy' => 'boolean', 'attempts' => 'integer', 'burned_at' => 'datetime', 'expires_at' => 'datetime', 'consumed_at' => 'datetime', 'superseded_at' => 'datetime'];
    }

    /**
     * The identifier this verification is scoped to, on each column's own width.
     *
     * Declared on this model as well as on AuthRecoveryProof, which carries the
     * same two columns: a bound on one proof table and not the other is invisible,
     * because each ceremony writes only its own.
     *
     * @return array<string, array{max: int, ascii?: bool}>
     */
    protected function valueBounds(): array
    {
        return [
            'identifier_value' => ['max' => 255],
            'identifier_type' => ['max' => 32],
        ];
    }
}
