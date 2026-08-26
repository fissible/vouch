<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;

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
