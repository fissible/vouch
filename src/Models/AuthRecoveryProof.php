<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;

final class AuthRecoveryProof extends Model
{
    protected $table = 'auth_recovery_proofs';

    protected $guarded = [];

    protected function casts(): array
    {
        return ['is_decoy' => 'boolean', 'expires_at' => 'datetime', 'consumed_at' => 'datetime'];
    }
}
