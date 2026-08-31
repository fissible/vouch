<?php

declare(strict_types=1);

namespace Fissible\Vouch\SelfService;

use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Assurance\AssuranceRequirement;
use Fissible\Vouch\Assurance\EvidenceComparator;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Policy\AllOf;
use Fissible\Vouch\Kernel\Policy\AnyOf;
use Fissible\Vouch\Kernel\Policy\FactorRequirement;
use Fissible\Vouch\Kernel\Policy\PolicyParser;
use Fissible\Vouch\Kernel\Policy\Requirement;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Fissible\Vouch\Sessions\SessionEvidence;
use Fissible\Vouch\Support\DatabaseTime;
use Throwable;

/**
 * Credential writes made by an authenticated user.
 *
 * Grace is intentionally classified before assurance: it is a narrow
 * capability, not a low assurance level.  Credential changes that invalidate
 * existing authentication revoke siblings in a committed write before their
 * mutation, then once more afterwards to close the login race between writes.
 */
final readonly class CredentialSelfService
{
    public function __construct(
        private FactorRegistry $factors,
        private EvidenceComparator $evidenceComparator,
        private \Psr\Clock\ClockInterface $clock,
        private SessionLifecycle $sessions,
        private DatabaseTime $databaseTime,
    ) {}

    public function changePassword(AuthSession $session, string $password): SelfServiceOutcome
    {
        $authoritative = $this->authorize($session, false);
        if ($authoritative instanceof SelfServiceOutcome) {
            return $authoritative;
        }

        return $this->mutateCredentials($authoritative, RevokedReason::PasswordChanged, function () use ($authoritative, $password): void {
            $this->factors->get('password')->enroll($authoritative->user_id, [
                'password' => $password,
                'replace' => true,
            ]);
        });
    }

    /** @param array<string, mixed> $data */
    public function addFactor(AuthSession $session, string $factorId, array $data): SelfServiceOutcome
    {
        // Grace can restore an authenticator, but cannot use this generic API
        // to change the password or mint a new set of recovery credentials.
        $authoritative = $this->authorize($session, ! in_array($factorId, ['password', 'recovery_code'], true));
        if ($authoritative instanceof SelfServiceOutcome) {
            return $authoritative;
        }

        try {
            $factor = $this->factors->get($factorId);
        } catch (Throwable) {
            return SelfServiceOutcome::Refused;
        }

        $replaces = ($data['replace'] ?? false) === true;

        if (! $replaces) {
            try {
                $factor->enroll($authoritative->user_id, $data);
            } catch (Throwable) {
                return SelfServiceOutcome::Refused;
            }

            return SelfServiceOutcome::Completed;
        }

        return $this->mutateCredentials($authoritative, RevokedReason::CredentialChanged, function () use ($factor, $authoritative, $data): void {
            $factor->enroll($authoritative->user_id, $data);
        });
    }

    public function regenerateRecoveryCodes(AuthSession $session): SelfServiceOutcome
    {
        $authoritative = $this->authorize($session, true);
        if ($authoritative instanceof SelfServiceOutcome) {
            return $authoritative;
        }

        try {
            $this->factors->get('recovery_code')->enroll($authoritative->user_id, []);
        } catch (Throwable) {
            return SelfServiceOutcome::Refused;
        }

        return SelfServiceOutcome::Completed;
    }

    public function addIdentifier(AuthSession $session, string $type, string $value): SelfServiceOutcome
    {
        $authoritative = $this->authorize($session, false);
        if ($authoritative instanceof SelfServiceOutcome) {
            return $authoritative;
        }

        try {
            AuthIdentifier::create([
                'user_id' => $authoritative->user_id,
                'type' => $type,
                'value' => $value,
                'verified_at' => null,
                'is_primary' => false,
            ]);
        } catch (Throwable) {
            return SelfServiceOutcome::Refused;
        }

        return SelfServiceOutcome::Completed;
    }

    public function removeFactor(AuthSession $session, int $credentialId): SelfServiceOutcome
    {
        $authoritative = $this->authorize($session, false);
        if ($authoritative instanceof SelfServiceOutcome) {
            return $authoritative;
        }

        // Deliberately after session classification: both absence and another
        // user's credential are Refused, so ids are not an oracle.
        $credential = AuthCredential::query()
            ->whereKey($credentialId)
            ->where('user_id', $authoritative->user_id)
            ->whereNull('disabled_at')
            ->first();

        if (! $credential instanceof AuthCredential) {
            return SelfServiceOutcome::Refused;
        }

        if ($this->wouldBreakLoginPolicy($authoritative->user_id, $credential)) {
            return SelfServiceOutcome::RequiredByPolicy;
        }

        try {
            $factor = $this->factors->get($credential->type);
        } catch (Throwable) {
            return SelfServiceOutcome::Refused;
        }

        return $this->mutateCredentials($authoritative, RevokedReason::CredentialChanged, function () use ($factor, $credential): void {
            $factor->revoke($credential);
        }, $credential->id);
    }

    /** @return AuthSession|SelfServiceOutcome */
    private function authorize(AuthSession $session, bool $graceAllowed): AuthSession|SelfServiceOutcome
    {
        $authoritative = AuthSession::query()->find($session->id);

        if (! $authoritative instanceof AuthSession || $authoritative->revoked_at !== null) {
            return SelfServiceOutcome::Refused;
        }

        if ($authoritative->isRecoveryGrace()) {
            if ($authoritative->recovery_grace_expires_at === null
                || $authoritative->recovery_grace_expires_at->getTimestamp() <= $this->databaseTime->current()->getTimestamp()) {
                return SelfServiceOutcome::Refused;
            }

            return $graceAllowed ? $authoritative : SelfServiceOutcome::RecoveryRestricted;
        }

        return $this->evidenceComparator->compare(SessionEvidence::read($authoritative), AssuranceRequirement::from('aal2'), $this->clock, null)->outcome->isSufficient()
            ? $authoritative
            : SelfServiceOutcome::StepUpRequired;
    }

    /** @param callable(): void $mutation */
    private function mutateCredentials(AuthSession $session, RevokedReason $reason, callable $mutation, ?int $removedCredentialId = null): SelfServiceOutcome
    {
        // Do not wrap these writes together: the first commit must survive a
        // failed credential mutation, and is externally observable by design.
        $this->sessions->revokeSiblings($session->user_id, $session->session_binding, $reason);

        try {
            $mutation();
        } catch (Throwable $throwable) {
            report($throwable);
            return SelfServiceOutcome::Refused;
        }

        $this->sessions->revokeSiblings($session->user_id, $session->session_binding, $reason);
        $this->removeCredentialFromEvidence($session, $removedCredentialId);

        return SelfServiceOutcome::Completed;
    }

    private function removeCredentialFromEvidence(AuthSession $session, ?int $credentialId): void
    {
        if ($credentialId === null) {
            return;
        }

        $authoritative = AuthSession::query()->find($session->id);
        $evidence = SessionEvidence::for($authoritative);

        if ($authoritative === null || $evidence === null) {
            return;
        }

        $remaining = array_values(array_filter(
            $evidence->factors,
            static fn ($factor): bool => $factor->credentialId !== (string) $credentialId,
        ));

        if (count($remaining) === count($evidence->factors)) {
            return;
        }

        if ($remaining === []) {
            $authoritative->update([
                'acr' => null,
                'assurance_proof' => null,
                'weakest_satisfied_at' => null,
            ]);

            return;
        }

        $rewritten = new \Fissible\Vouch\Assurance\AssuranceEvidence(
            $evidence->subject,
            $evidence->tenantId,
            $remaining,
        );

        $authoritative->update([
            'acr' => $rewritten->derivedAcr(),
            'assurance_proof' => $rewritten->toArray(),
            'weakest_satisfied_at' => $rewritten->weakestSatisfiedAt(),
        ]);
    }

    private function wouldBreakLoginPolicy(int $userId, AuthCredential $removing): bool
    {
        $policy = AuthPolicy::query()->where('scope', 'login')->whereNull('tenant_id')->first();
        if (! $policy instanceof AuthPolicy) {
            return false;
        }

        try {
            $requirement = (new PolicyParser())->parse($policy->document);
        } catch (Throwable) {
            return true;
        }

        $remaining = [];

        foreach (AuthCredential::query()
            ->where('user_id', $userId)
            ->whereNull('disabled_at')
            ->whereKeyNot($removing->id)
            ->get()
            as $credential) {
            $remaining[] = $credential;
        }

        return ! $this->satisfies($requirement, $remaining);
    }

    /** @param list<AuthCredential> $credentials */
    private function satisfies(Requirement $requirement, array $credentials): bool
    {
        if ($requirement instanceof FactorRequirement) {
            foreach ($credentials as $credential) {
                if ($credential->type !== $requirement->factorId) {
                    continue;
                }

                if ($requirement->userVerified !== null && $credential->user_verified !== $requirement->userVerified) {
                    continue;
                }

                if ($requirement->phishingResistant !== null && $credential->phishing_resistant !== $requirement->phishingResistant) {
                    continue;
                }

                if ($requirement->minimumStrength !== null
                    && (! $this->strength($credential) instanceof FactorStrength
                        || ! $this->strength($credential)->atLeast($requirement->minimumStrength))) {
                    continue;
                }

                return true;
            }

            return false;
        }

        if ($requirement instanceof AllOf) {
            foreach ($requirement->requirements as $child) {
                if (! $this->satisfies($child, $credentials)) {
                    return false;
                }
            }

            return true;
        }

        if ($requirement instanceof AnyOf) {
            foreach ($requirement->requirements as $child) {
                if ($this->satisfies($child, $credentials)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function strength(AuthCredential $credential): ?FactorStrength
    {
        foreach (FactorStrength::cases() as $strength) {
            if ($strength->name === $credential->strength) {
                return $strength;
            }
        }

        return null;
    }
}
