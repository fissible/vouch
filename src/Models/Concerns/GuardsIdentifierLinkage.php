<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models\Concerns;

use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Persistence\IdentifierLinkageViolation;

/**
 * Enforces Amendment A's same-user and verified rules on the credential write path.
 *
 * In the model layer rather than in a driver, following EnforcesValueBounds and
 * for the same reason: a check that lives in one caller is a check the next
 * caller skips. Hooking `saving` means every create and update goes through it.
 */
trait GuardsIdentifierLinkage
{
    public static function bootGuardsIdentifierLinkage(): void
    {
        static::saving(static function (self $model): void {
            $identifierId = $model->identifier_id;

            if ($identifierId === null) {
                return;
            }

            $identifier = AuthIdentifier::query()->find($identifierId);

            if (! $identifier instanceof AuthIdentifier) {
                throw IdentifierLinkageViolation::missing($identifierId);
            }

            $credentialUserId = $model->user_id;

            if ($identifier->user_id !== $credentialUserId) {
                throw IdentifierLinkageViolation::crossUser($credentialUserId, $identifier->user_id);
            }

            if ($identifier->verified_at === null) {
                throw IdentifierLinkageViolation::unverified($identifierId);
            }
        });
    }
}
