<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models\Concerns;

use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Persistence\IdentifierLinkageViolation;

/**
 * Freezes AuthIdentifier::$value once any credential references the row.
 *
 * `updating` rather than `saving`: on create nothing can reference the row yet,
 * and hooking `saving` would cost a query on every insert to learn that.
 *
 * Only `value` freezes. Freezing the whole row would block re-verification and
 * primary-address changes, neither of which redirects delivery, and a guard that
 * blocks legitimate work gets removed.
 *
 * The disabled_at state of the referencing credential is deliberately not
 * considered: a disabled credential can be re-enabled, so its delivery target
 * must not have moved underneath it in the meantime.
 */
trait FreezesReferencedValue
{
    public static function bootFreezesReferencedValue(): void
    {
        static::updating(static function (self $model): void {
            if (! $model->isDirty('value')) {
                return;
            }

            $referenced = AuthCredential::query()
                ->where('identifier_id', $model->id)
                ->exists();

            if ($referenced) {
                throw IdentifierLinkageViolation::frozen($model->id);
            }
        });
    }
}
