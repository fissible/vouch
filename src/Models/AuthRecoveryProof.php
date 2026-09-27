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
final class AuthRecoveryProof extends Model
{
    use EnforcesValueBounds;

    protected $table = 'auth_recovery_proofs';

    protected $guarded = [];

    protected function casts(): array
    {
        return ['is_decoy' => 'boolean', 'attempts' => 'integer', 'burned_at' => 'datetime', 'expires_at' => 'datetime', 'consumed_at' => 'datetime', 'superseded_at' => 'datetime'];
    }

    /**
     * The identifier this proof is scoped to, on each column's own width.
     *
     * Declared here as well as on AuthIdentifier, rather than once anywhere: these
     * are different columns on a different table, reached through a ceremony that
     * writes a decoy row for an identifier no AuthIdentifier exists for -- so a
     * bound on the identifier table never runs for them. The ceremony
     * canonicalizes before writing, so this measures the canonical form.
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
