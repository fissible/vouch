<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string|null $tenant_id
 * @property string|null $email_domain
 * @property string|null $discovery_url
 * @property string|null $client_id
 * @property string|null $client_secret
 * @property array<string, mixed>|null $claim_mappings
 * @property array<string, mixed>|null $jit_rules
 * @property bool $trust_email_verified
 * @property bool $auto_link
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthConnection extends Model
{
    protected $table = 'auth_connections';

    protected $guarded = [];

    /** @var list<string> */
    protected $hidden = ['client_secret'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'client_secret' => 'encrypted',
            'claim_mappings' => 'array',
            'jit_rules' => 'array',
            'trust_email_verified' => 'boolean',
            'auto_link' => 'boolean',
        ];
    }
}
