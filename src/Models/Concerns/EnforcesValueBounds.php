<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models\Concerns;

use Fissible\Vouch\Persistence\ValueBoundViolation;

/**
 * Enforces declared length and character-set bounds on the write path.
 *
 * This lives in the model layer rather than in a driver or a contract docblock
 * because a docblock constrains nobody: `AuthConnection`, `AuthPolicy`, and
 * `AuthAttempt` can all be written directly by future code that never read it.
 * Hooking `saving` means every create and update goes through the check,
 * whatever calls it.
 *
 * It also makes behaviour identical across engines. SQLite does not enforce
 * VARCHAR length at all, MySQL rejects under a strict `sql_mode` and silently
 * truncates without one, and Postgres rejects. Validating in PHP collapses
 * three behaviours into one, and — crucially — means a test asserting rejection
 * passes on SQLite rather than vacuously succeeding there while the real
 * engines diverge.
 */
trait EnforcesValueBounds
{
    /**
     * Bounds per attribute. `max` is a character count, matching how MySQL and
     * Postgres count VARCHAR. `ascii` additionally requires the value be ASCII.
     *
     * @return array<string, array{max: int, ascii?: bool}>
     */
    abstract protected function valueBounds(): array;

    public static function bootEnforcesValueBounds(): void
    {
        // `self` in a trait resolves to the composing model, which is both
        // correct at runtime and what lets static analysis see valueBounds().
        static::saving(static function (self $model): void {
            foreach ($model->valueBounds() as $attribute => $rule) {
                $value = $model->getAttribute($attribute);

                if (! is_string($value)) {
                    continue;
                }

                if (($rule['ascii'] ?? false) && ! mb_check_encoding($value, 'ASCII')) {
                    throw ValueBoundViolation::notAscii($model::class, $attribute);
                }

                $length = mb_strlen($value);

                if ($length > $rule['max']) {
                    throw ValueBoundViolation::tooLong($model::class, $attribute, $rule['max'], $length);
                }
            }
        });
    }
}
