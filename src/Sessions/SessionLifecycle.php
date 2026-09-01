<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Assurance\AssuranceEvidence;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Tokens\SubjectKey;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Model;
use Psr\Clock\ClockInterface;
use Throwable;

/**
 * Owns §7.5: rotate on every assurance increase, record the binding, revoke
 * siblings on credential change.
 *
 * THE ORDER IS THE MECHANISM. The host session store and the database are
 * different stores; there is no shared transaction and this class does not
 * pretend otherwise. Instead the guard login happens last — performed by the
 * caller, after establish() returns — so every earlier failure lands on an
 * unauthenticated session.
 */
final readonly class SessionLifecycle
{
    public function __construct(
        private Session $session,
        private ClockInterface $clock,
        private AssuranceVocabulary $vocabulary,
    ) {}

    /**
     * @throws SessionRotationFailed when the record cannot be written.
     */
    public function establish(AuthSuccess $success): void
    {
        // 1. Regenerate. §7.5 requires this on every assurance increase, not
        //    only at login: a step-up that raised assurance without rotating
        //    leaves the pre-step-up session ID valid at the higher level.
        $this->session->regenerate();

        $binding = SessionBinding::for($this->session->getId(), BindingDomain::Session);

        try {
            $model = self::configuredUserModel();
            $proof = new AssuranceEvidence(
                SubjectKey::of((new $model)->getMorphClass(), $success->userId),
                $success->tenantId,
                $success->factors,
            );
            // 2. Rotate in place. 2.1 ships this shape with a test that the row
            //    count stays at one; a second row would orphan the old binding
            //    and leave a session nothing can revoke.
            AuthSession::query()->updateOrCreate(
                ['user_id' => $success->userId, 'revoked_at' => null],
                [
                    'session_binding' => $binding,
                    'amr' => $success->amr(),
                    'acr' => $this->vocabulary->name($proof->facts()),
                    'assurance_proof' => $proof->toArray(),
                    'weakest_satisfied_at' => $proof->weakestSatisfiedAt(),
                    'recovery_grace_expires_at' => null,
                ],
            );
        } catch (Throwable $failure) {
            // 4. Destroy the regenerated session and fail closed. Nothing has
            //    logged in yet, which is the entire point of the ordering.
            $this->session->invalidate();

            throw SessionRotationFailed::after($failure);
        }

        // 3. The caller logs into the host guard only after this returns.
    }

    /**
     * Revoke every other live session for this user.
     *
     * Setting revoked_at is inert on its own — the host's cookie still works.
     * ValidatesVouchSession is the authoritative read that makes it real.
     */
    public function revokeSiblings(int $userId, string $keepBinding, RevokedReason $reason): int
    {
        return AuthSession::query()
            ->where('user_id', $userId)
            ->where('session_binding', '!=', $keepBinding)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => $this->clock->now(), 'revoked_reason' => $reason]);
    }

    /** @return class-string<Model> */
    private static function configuredUserModel(): string
    {
        $model = config('auth.providers.users.model');

        if (! is_string($model) || ! is_subclass_of($model, Model::class)) {
            throw new \RuntimeException('auth.providers.users.model is not an Eloquent model.');
        }

        return $model;
    }
}
