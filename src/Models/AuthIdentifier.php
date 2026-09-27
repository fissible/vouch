<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Fissible\Vouch\Identifiers\IdentifierGuard;
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
            ? $this->identity()->canonicalize($this->wellFormed($value))
            : $value;
    }

    /** The other half of the unique index, on the same terms. */
    public function setTypeAttribute(mixed $type): void
    {
        $this->attributes['type'] = is_string($type)
            ? $this->identity()->canonicalize($this->wellFormed($type))
            : $type;
    }

    /**
     * The submitted spelling, or a refusal.
     *
     * In the mutator, BEFORE canonicalization, and that placement is the whole
     * value of it: canonicalization hands invalid UTF-8 to Symfony's
     * UnicodeString and gets a library exception back, and a check in a `saving`
     * hook would run after the attribute was already rewritten -- and after the
     * insert, if it were `saved`, which is how a refusal still leaves a row.
     */
    private function wellFormed(string $submitted): string
    {
        IdentifierGuard::assertWellFormed($submitted);

        return $submitted;
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
            // The OTHER half of that index, and varchar(32) rather than 255.
            // Bounded here on its own narrower width: two 34-character types
            // differing in their last character both truncate to the same 32 under
            // a non-strict MySQL sql_mode and collide in unique(type, value),
            // which merges two accounts. Measured on the canonical form, because
            // the mutator above has already canonicalized it and canonicalization
            // changes character count in both directions.
            'type' => ['max' => 32],
        ];
    }
}
