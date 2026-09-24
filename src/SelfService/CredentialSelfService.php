<?php

declare(strict_types=1);

namespace Fissible\Vouch\SelfService;

use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Factors\EnrollmentResult;
use Fissible\Vouch\Assurance\AssuranceRequirement;
use Fissible\Vouch\Assurance\EvidenceComparator;
use Fissible\Vouch\Credentials\CredentialCleanupStep;
use Fissible\Vouch\Credentials\CredentialDriverFailureIdentity;
use Fissible\Vouch\Credentials\CredentialDriverFailureCollector;
use Fissible\Vouch\Credentials\CredentialMutation;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
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
use Fissible\Vouch\Tokens\SubjectKey;
use Illuminate\Database\Connection;
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
        private AssuranceVocabulary $vocabulary,
        private Connection $connection,
        private CredentialMutation $credentialMutation,
        private CredentialDriverFailureCollector $failureCollector,
    ) {}

    public function changePassword(AuthSession $session, string $password): SelfServiceResult
    {
        $authoritative = $this->authorize($session, false);
        if ($authoritative instanceof SelfServiceOutcome) {
            return new SelfServiceResult($authoritative);
        }

        return $this->mutateCredentials($authoritative, RevokedReason::PasswordChanged, function () use ($authoritative, $password): EnrollmentResult {
            return $this->factors->get('password')->enroll($authoritative->user_id, [
                'password' => $password,
                'replace' => true,
            ]);
        });
    }

    /** @param array<string, mixed> $data */
    public function addFactor(AuthSession $session, string $factorId, array $data): SelfServiceResult
    {
        // Grace can restore an authenticator, but cannot use this generic API
        // to change the password or mint a new set of recovery credentials.
        $authoritative = $this->authorize($session, ! in_array($factorId, ['password', 'recovery_code'], true));
        if ($authoritative instanceof SelfServiceOutcome) {
            return new SelfServiceResult($authoritative);
        }

        try {
            $factor = $this->factors->get($factorId);
        } catch (Throwable) {
            return new SelfServiceResult(SelfServiceOutcome::Refused);
        }

        $replaces = ($data['replace'] ?? false) === true;

        if (! $replaces) {
            try {
                $enrollment = $factor->enroll($authoritative->user_id, $data);
            } catch (Throwable) {
                return new SelfServiceResult(SelfServiceOutcome::Refused);
            }

            return new SelfServiceResult(SelfServiceOutcome::Completed, $enrollment->secrets);
        }

        return $this->mutateCredentials($authoritative, RevokedReason::CredentialChanged, function () use ($factor, $authoritative, $data): EnrollmentResult {
            return $factor->enroll($authoritative->user_id, $data);
        }, credentialIds: array_values(AuthCredential::query()
            ->where('user_id', $authoritative->user_id)
            ->where('type', $factorId)
            ->whereNull('disabled_at')
            ->get()
            ->map(static fn (AuthCredential $credential): string => (string) $credential->id)
            ->all()));
    }

    public function regenerateRecoveryCodes(AuthSession $session): SelfServiceResult
    {
        $authoritative = $this->authorize($session, true);
        if ($authoritative instanceof SelfServiceOutcome) {
            return new SelfServiceResult($authoritative);
        }

        return $this->mutateCredentials($authoritative, RevokedReason::CredentialChanged, function () use ($authoritative): EnrollmentResult {
            return $this->factors->get('recovery_code')->enroll($authoritative->user_id, []);
        }, credentialIds: array_values(AuthCredential::query()
            ->where('user_id', $authoritative->user_id)
            ->where('type', 'recovery_code')
            ->whereNull('disabled_at')
            ->get()
            ->map(static fn (AuthCredential $credential): string => (string) $credential->id)
            ->all()));
    }

    public function addIdentifier(AuthSession $session, string $type, string $value): SelfServiceResult
    {
        $authoritative = $this->authorize($session, false);
        if ($authoritative instanceof SelfServiceOutcome) {
            return new SelfServiceResult($authoritative);
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
            return new SelfServiceResult(SelfServiceOutcome::Refused);
        }

        return new SelfServiceResult(SelfServiceOutcome::Completed);
    }

    public function removeFactor(AuthSession $session, int $credentialId): SelfServiceResult
    {
        $authoritative = $this->authorize($session, false);
        if ($authoritative instanceof SelfServiceOutcome) {
            return new SelfServiceResult($authoritative);
        }

        // Deliberately after session classification: both absence and another
        // user's credential are Refused, so ids are not an oracle.
        $credential = AuthCredential::query()
            ->whereKey($credentialId)
            ->where('user_id', $authoritative->user_id)
            ->whereNull('disabled_at')
            ->first();

        if (! $credential instanceof AuthCredential) {
            return new SelfServiceResult(SelfServiceOutcome::Refused);
        }

        if ($this->wouldBreakLoginPolicy($authoritative->user_id, $credential)) {
            return new SelfServiceResult(SelfServiceOutcome::RequiredByPolicy);
        }

        try {
            $factor = $this->factors->get($credential->type);
        } catch (Throwable) {
            return new SelfServiceResult(SelfServiceOutcome::Refused);
        }

        return $this->mutateCredentials($authoritative, RevokedReason::CredentialChanged, function () use ($factor, $credential): EnrollmentResult {
            $report = $this->failureCollector->collect($this->connection, fn () => $factor->revoke($credential));

            return new EnrollmentResult([], report: $report);
        }, $credential->id, [(string) $credential->id]);
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

    /**
     * @param callable(): EnrollmentResult $mutation
     * @param list<string>|null $credentialIds
     */
    private function mutateCredentials(AuthSession $session, RevokedReason $reason, callable $mutation, ?int $removedCredentialId = null, ?array $credentialIds = null): SelfServiceResult
    {
        // Do not wrap these writes together: the first commit must survive a
        // failed credential mutation, and is externally observable by design.
        $this->sessions->revokeSiblings($session->user_id, $session->session_binding, $reason);

        $subject = SubjectKey::forConfiguredUser($session->user_id);
        $revocation = $credentialIds === null
            ? $this->credentialMutation->subjectWide($subject, static fn () => null)
            : $this->credentialMutation->revoking($subject, $credentialIds, static fn () => null);
        $driverFailures = $revocation->report->driverFailures;

        try {
            $enrollment = $this->connection->transaction(fn () => $mutation());
        } catch (Throwable $throwable) {
            report($throwable);
            return new SelfServiceResult(SelfServiceOutcome::CredentialChangeFailed, [], $driverFailures);
        }

        $cleanupFailures = [];

        try {
            $this->sessions->revokeSiblings($session->user_id, $session->session_binding, $reason);
        } catch (Throwable $throwable) {
            report($throwable);
            $cleanupFailures[] = CredentialCleanupStep::SiblingRevocation;
        }

        try {
            $this->removeCredentialFromEvidence($session, $removedCredentialId);
        } catch (Throwable $throwable) {
            report($throwable);
            $cleanupFailures[] = CredentialCleanupStep::EvidenceCleanup;
        }

        return new SelfServiceResult(SelfServiceOutcome::Completed, $enrollment->secrets, CredentialDriverFailureIdentity::merge(
            $revocation->report->driverFailures,
            $enrollment->driverFailures,
        ), $cleanupFailures);
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
            'acr' => $this->vocabulary->name($rewritten->facts()),
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
