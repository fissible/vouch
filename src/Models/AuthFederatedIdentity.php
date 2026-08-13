<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Fissible\Vouch\Models\Concerns\EnforcesValueBounds;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $connection_id
 * @property string $issuer
 * @property string $subject
 * @property array<string, mixed>|null $claims
 * @property int|null $user_id
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthFederatedIdentity extends Model
{
    use EnforcesValueBounds;

    protected $table = 'auth_federated_identities';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['claims' => 'array'];
    }

    /**
     * @return array<string, array{max: int, ascii?: bool}>
     */
    protected function valueBounds(): array
    {
        return [
            // OIDC Core §2 caps `sub` at 255 ASCII characters. Enforced rather
            // than assumed: the IdP is an input boundary, not a trusted peer.
            'subject' => ['max' => 255, 'ascii' => true],

            // `iss` has no length cap in OIDC or OAuth. 255 ASCII is a
            // deliberate v1 support limit, refused rather than truncated or
            // normalised — see PROJECT.md for the digest-based redesign if
            // arbitrarily long protocol-valid issuers ever matter.
            'issuer' => ['max' => 255, 'ascii' => true],
        ];
    }
}
