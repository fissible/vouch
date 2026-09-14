<?php

declare(strict_types=1);

namespace Fissible\Vouch\Recovery;

use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Contracts\RandomSource;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthRecoveryProof;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Throttle\IssuancePermission;
use Fissible\Vouch\Throttle\ProofAttemptStore;
use Fissible\Vouch\Throttle\ThrottleDecision;
use Fissible\Vouch\Throttle\ThrottleKey;
use Illuminate\Database\Connection;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Hash;
use Throwable;

final readonly class CredentialRecovery
{
    public function __construct(
        private RecoveryProofOutbox $outbox,
        private GraceGuard $grace,
        private Factor $password,
        private Connection $connection,
        private DatabaseTime $time,
        private RandomSource $random,
        private Repository $config,
        private SessionLifecycle $sessions,
        private AuthThrottleStore $throttles,
        private ThrottleKey $keys,
        private ProofAttemptStore $attempts,
    ) {}

    public function request(CredentialRecoveryRequest $request): void
    {
        $this->outbox->assertReady();

        if ($this->throttles->permitIssuance(
            $this->keys->ceremony(
                $request->submittedIdentifier,
                $request->tenantId === null ? null : (string) $request->tenantId,
            ),
        ) === IssuancePermission::Refused) {
            return;
        }

        $identifier = AuthIdentifier::query()
            ->where('type', $request->type)
            ->where('value', $request->submittedIdentifier)
            ->whereNotNull('verified_at')
            ->first();

        $this->outbox->issue(
            $request,
            $identifier instanceof AuthIdentifier ? $identifier : null,
            $this->code(),
            $this->config->integer('vouch.recovery.ttl_seconds'),
        );
    }

    public function redeem(CredentialRecoveryRequest $request, string $code, string $hostSessionId): CredentialRecoveryOutcome
    {
        if ($code === '') {
            return CredentialRecoveryOutcome::Refused;
        }

        $subject = $this->keys->recovery(
            $request->submittedIdentifier,
            $request->tenantId === null ? null : (string) $request->tenantId,
        );

        // Backoff must precede proof accounting, or refused traffic could still
        // burn the user's code and deny recovery without spending throttle budget.
        if ($this->throttles->preflightShared($subject)->decision === ThrottleDecision::BackedOff) {
            return CredentialRecoveryOutcome::Refused;
        }

        $outcome = $this->connection->transaction(function () use ($request, $code, $hostSessionId): CredentialRecoveryOutcome {
            $proof = AuthRecoveryProof::query()
                ->where('identifier_type', $request->type)
                ->where('identifier_value', $request->submittedIdentifier)
                ->whereNull('superseded_at')
                ->whereNull('consumed_at')
                ->whereNull('burned_at')
                /*
                 * The outbox writes this deadline in database time; PHP clock skew
                 * must not change the recovery window.
                 */
                ->where('expires_at', '>', $this->time->now())
                ->latest('id')
                ->lockForUpdate()
                ->first();

            if (! $proof instanceof AuthRecoveryProof) {
                return CredentialRecoveryOutcome::Refused;
            }

            if (! Hash::check($code, $proof->code_hash) || $proof->is_decoy) {
                $this->attempts->recordFailure($proof);

                return CredentialRecoveryOutcome::Refused;
            }

            $identifier = AuthIdentifier::query()
                ->where('type', $request->type)
                ->where('value', $request->submittedIdentifier)
                ->whereNotNull('verified_at')
                ->lockForUpdate()
                ->first();

            if (! $identifier instanceof AuthIdentifier) {
                $this->attempts->recordFailure($proof);

                return CredentialRecoveryOutcome::Refused;
            }

            // A revoked or differently owned binding cannot receive grace.
            // Keep the proof usable when that expected refusal prevents recovery.
            if (! $this->grace->start($hostSessionId, $identifier->user_id)) {
                return CredentialRecoveryOutcome::Refused;
            }

            AuthRecoveryProof::query()
                ->whereKey($proof->id)
                ->whereNull('consumed_at')
                ->whereNull('superseded_at')
                ->whereNull('burned_at')
                ->update(['consumed_at' => $this->time->now()]);

            return CredentialRecoveryOutcome::GraceOpened;
        });

        // Commit proof evidence before recording advisory backoff state, keeping
        // throttle counter locks out of the proof/identifier lock sequence.
        if ($outcome === CredentialRecoveryOutcome::Refused) {
            $this->throttles->recordRecoveryFailure($subject);
        }

        return $outcome;
    }

    public function reset(string $hostSessionId, string $password): CredentialRecoveryOutcome
    {
        // This authorization occurs before either revocation pass.
        $grace = $this->grace->activeFor($hostSessionId);
        if (! $grace instanceof AuthSession) {
            return CredentialRecoveryOutcome::Refused;
        }

        if ($this->config->boolean('vouch.recovery.require_second_factor') && $this->hasEnabledSecondFactor($grace->user_id)) {
            return CredentialRecoveryOutcome::SecondFactorRequired;
        }

        // Authorize first: no rejected request may revoke another session.
        // The first pass commits before mutation; the second catches sessions
        // established after that pass while the password factor was mutating.
        $this->revokeOtherSessions($grace);

        try {
            $this->password->enroll($grace->user_id, ['password' => $password, 'replace' => true]);
        } catch (Throwable $failure) {
            report($failure);

            return CredentialRecoveryOutcome::Refused;
        }

        $this->revokeOtherSessions($grace);

        return CredentialRecoveryOutcome::Reset;
    }

    private function revokeOtherSessions(AuthSession $grace): void
    {
        $this->sessions->revokeSiblings(
            $grace->user_id,
            $grace->session_binding,
            RevokedReason::PasswordChanged,
        );
    }

    private function hasEnabledSecondFactor(int $userId): bool
    {
        return AuthCredential::query()
            ->where('user_id', $userId)
            ->whereNull('disabled_at')
            // Recovery codes restore an enrolled factor; they are not another factor.
            // A newly added credential type deliberately counts until policy says otherwise:
            // overlooking it here would silently weaken recovery assurance.
            ->whereNotIn('type', ['password', 'recovery_code'])
            ->exists();
    }

    private function code(): string
    {
        $code = '';

        for ($i = 0; $i < 6; $i++) {
            $code .= (string) $this->random->int(0, 9);
        }

        return $code;
    }
}
