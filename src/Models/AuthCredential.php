<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Fissible\Vouch\Models\Concerns\GuardsIdentifierLinkage;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $user_id
 * @property string $type
 * @property int|null $identifier_id
 * @property string|null $relying_party_id
 * @property string|null $secret
 * @property string $strength
 * @property bool $is_multi_factor
 * @property bool $user_verified
 * @property bool $phishing_resistant
 * @property string|null $authenticator_id
 * @property Carbon|null $last_used_at
 * @property int|null $last_used_timestep
 * @property Carbon|null $disabled_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthCredential extends Model
{
    use GuardsIdentifierLinkage;

    protected $table = 'auth_credentials';

    protected $guarded = [];

    /**
     * Keeps the secret out of any accidental toArray() or JSON serialisation.
     * A log line or an API response carrying a TOTP seed is a credential
     * disclosure, and both are easy to produce by accident.
     *
     * @var list<string>
     */
    protected $hidden = ['secret'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'secret' => 'encrypted',
            'is_multi_factor' => 'boolean',
            'user_verified' => 'boolean',
            'phishing_resistant' => 'boolean',
            'last_used_at' => 'datetime',
            'last_used_timestep' => 'integer',
            'disabled_at' => 'datetime',
        ];
    }
}
