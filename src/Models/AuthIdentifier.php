<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Fissible\Vouch\Models\Concerns\EnforcesValueBounds;
use Fissible\Vouch\Models\Concerns\FreezesReferencedValue;
use Fissible\Vouch\Throttle\IdentifierCanonicalizer;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $user_id
 * @property string $type
 * @property string $value
 * @property Carbon|null $verified_at
 * @property bool $is_primary
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AuthIdentifier extends Model
{
    use EnforcesValueBounds;
    use FreezesReferencedValue;

    protected $table = 'auth_identifiers';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'verified_at' => 'datetime',
            'is_primary' => 'boolean',
        ];
    }

    /**
     * Identity is decided here, on the way in, rather than by the collation of
     * the column it lands in.
     *
     * A mutator rather than a rule at the call sites: `value` is half of
     * unique(type, value), so a row stored in some other spelling makes that
     * index mean something different from what every lookup asks of it. Hooking
     * the attribute catches every create and update, including a host's own.
     *
     * Canonicalizing on write is only half the change and would be a regression
     * alone -- the lookups have to ask the same question, which is why they
     * canonicalize the submitted value too.
     */
    public function setValueAttribute(mixed $value): void
    {
        $this->attributes['value'] = is_string($value)
            ? $this->identity()->canonicalize($value)
            : $value;
    }

    /** The other half of the unique index, on the same terms. */
    public function setTypeAttribute(mixed $type): void
    {
        $this->attributes['type'] = is_string($type)
            ? $this->identity()->canonicalize($type)
            : $type;
    }

    private function identity(): IdentifierCanonicalizer
    {
        return app(IdentifierCanonicalizer::class);
    }

    /**
     * @return array<string, array{max: int, ascii?: bool}>
     */
    protected function valueBounds(): array
    {
        return [
            // Registration input, and half of the unique (type, value) index.
            // Same input-boundary class as the federated-identity columns.
            'value' => ['max' => 255],
        ];
    }
}
