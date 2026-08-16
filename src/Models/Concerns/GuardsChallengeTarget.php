<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models\Concerns;

use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Persistence\ChallengeTargetViolation;
use Illuminate\Support\Facades\Config;

/**
 * Enforces Amendment D on the challenge write path.
 *
 * `creating` rather than `saving`: a challenge's target is fixed at delivery.
 * The only later writes are consumption and the attempt counter, neither of
 * which may change what was sent, and re-running the checks on those would cost
 * two queries per verification for an invariant that cannot have changed.
 */
trait GuardsChallengeTarget
{
    public static function bootGuardsChallengeTarget(): void
    {
        static::creating(static function (self $model): void {
            $factorType = $model->factor_type;
            $credentialId = $model->credential_id;
            $isDecoy = $model->is_decoy;

            /** @var list<string> $requiresTarget */
            $requiresTarget = Config::array('vouch.challenges.require_credential');

            if ($isDecoy) {
                if ($credentialId !== null) {
                    throw ChallengeTargetViolation::decoyNamedTarget($credentialId);
                }

                // Keep the request-side query shape aligned with a real target:
                // one credential lookup and one attempt lookup. A decoy cannot
                // name a credential, so key zero is the explicit non-target.
                AuthCredential::query()->whereKey(0)->first();
                AuthAttempt::query()->find($model->attempt_id);

                return;
            }

            if ($credentialId === null) {
                if (in_array($factorType, $requiresTarget, true)) {
                    throw ChallengeTargetViolation::targetRequired($factorType);
                }

                return;
            }

            $credential = AuthCredential::query()->find($credentialId);

            if (! $credential instanceof AuthCredential) {
                throw ChallengeTargetViolation::missing($credentialId);
            }

            if ($credential->disabled_at !== null) {
                throw ChallengeTargetViolation::disabled($credentialId);
            }

            $attempt = AuthAttempt::query()->find($model->attempt_id);
            $attemptUserId = $attempt?->user_id;

            if ($attemptUserId === null || $credential->user_id !== $attemptUserId) {
                throw ChallengeTargetViolation::foreignUser($credentialId, $attemptUserId);
            }

            /*
             * The identifier is derived through the credential rather than
             * stored on the challenge as well, so the two cannot drift. This
             * check is what makes that derivation total.
             */
            if (in_array($factorType, $requiresTarget, true) && $credential->identifier_id === null) {
                throw ChallengeTargetViolation::notIdentifierLinked($credentialId);
            }
        });
    }
}
