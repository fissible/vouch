<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Fissible\Vouch\Models\Casts\UtcDateTime;
use Fissible\Vouch\Sessions\RevokedReason;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $session_binding
 * @property int $user_id
 * @property list<string> $amr
 * @property string|null $acr
 * @property array<string, mixed>|null $assurance_proof
 * @property Carbon|null $weakest_satisfied_at
 * @property Carbon|null $recovery_grace_expires_at
 * @property Carbon|null $revoked_at
 * @property RevokedReason|null $revoked_reason
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthSession extends Model
{
    protected $table = 'auth_sessions';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            // Database drivers may hydrate BIGINT columns as strings, while a
            // host User commonly returns an integer identifier. Normalize at
            // the model boundary so strict ownership checks fail only for a
            // different user, not for PDO representation differences.
            'user_id' => 'integer',
            'amr' => 'array',
            'assurance_proof' => 'array',
            'weakest_satisfied_at' => UtcDateTime::class,
            'recovery_grace_expires_at' => 'datetime',
            'revoked_at' => 'datetime',
            'revoked_reason' => RevokedReason::class,
        ];
    }

    /**
     * Whether this is a recovery-grace session.
     *
     * The presence of recovery_grace_expires_at is the operative marker; the
     * amr containing only the recovery factor is the evidence that produced it.
     * Both are set together at creation and cleared together on completion.
     * This reads the marker rather than inspecting the amr, so that an amr
     * which is empty or malformed cannot be mistaken for a normal session —
     * the failure direction matters, and this one fails closed.
     */
    public function isRecoveryGrace(): bool
    {
        return $this->recovery_grace_expires_at !== null;
    }
}
