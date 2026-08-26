<?php

declare(strict_types=1);

namespace Fissible\Vouch\Recovery;

use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Contracts\RandomSource;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthRecoveryProof;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Database\Connection;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Hash;
use Psr\Clock\ClockInterface;
use Throwable;

final readonly class CredentialRecovery
{
    public function __construct(
        private RecoveryProofOutbox $outbox,
        private GraceGuard $grace,
        private Factor $password,
        private Connection $connection,
        private DatabaseTime $time,
        private ClockInterface $clock,
        private RandomSource $random,
        private Repository $config,
        private SessionLifecycle $sessions,
    ) {}

    public function request(CredentialRecoveryRequest $request): void
    {
        $this->outbox->assertReady();

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

        return $this->connection->transaction(function () use ($request, $code, $hostSessionId): CredentialRecoveryOutcome {
            $proof = AuthRecoveryProof::query()
                ->where('identifier_type', $request->type)
                ->where('identifier_value', $request->submittedIdentifier)
                ->whereNull('consumed_at')
                ->where('expires_at', '>', $this->clock->now())
                ->latest('id')
                ->lockForUpdate()
                ->first();

            if (! $proof instanceof AuthRecoveryProof || ! Hash::check($code, $proof->code_hash) || $proof->is_decoy) {
                return CredentialRecoveryOutcome::Refused;
            }

            $identifier = AuthIdentifier::query()
                ->where('type', $request->type)
                ->where('value', $request->submittedIdentifier)
                ->whereNotNull('verified_at')
                ->lockForUpdate()
                ->first();

            if (! $identifier instanceof AuthIdentifier) {
                return CredentialRecoveryOutcome::Refused;
            }

            AuthRecoveryProof::query()
                ->whereKey($proof->id)
                ->whereNull('consumed_at')
                ->update(['consumed_at' => $this->time->now()]);

            $this->grace->start($hostSessionId, $identifier->user_id);

            return CredentialRecoveryOutcome::GraceOpened;
        });
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
