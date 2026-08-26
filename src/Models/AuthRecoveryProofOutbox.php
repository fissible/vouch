<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $opaque_id
 * @property int $proof_id
 * @property array{target: array{id: int, user_id: int, type: string, value: string, verified_at: string|null}|null, code: string, decoy: bool}|null $payload
 * @property string $status
 * @property Carbon $expires_at
 * @property Carbon|null $dispatched_at
 * @property Carbon|null $provider_attempted_at
 * @property Carbon|null $delivered_at
 * @property Carbon|null $undeliverable_at
 * @property string|null $failure_reason
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthRecoveryProofOutbox extends Model
{
    protected $table = 'auth_recovery_proof_outbox';

    protected $guarded = [];

    protected $hidden = ['payload'];

    protected function casts(): array
    {
        return [
            'payload' => 'encrypted:array',
            'expires_at' => 'datetime',
            'dispatched_at' => 'datetime',
            'provider_attempted_at' => 'datetime',
            'delivered_at' => 'datetime',
            'undeliverable_at' => 'datetime',
        ];
    }
}
