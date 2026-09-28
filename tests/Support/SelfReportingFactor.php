<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Credentials\CredentialDriverFailureReport;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\EnrollmentResult;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;

/**
 * A host factor that reports a driver failure of its own, in its own report.
 *
 * `EnrollmentResult`'s third constructor argument and
 * `CredentialDriverFailureReport::record()` are both public, so a driver
 * populating its own channel is supported API rather than an internal detail.
 * This fixture stands for the driver that needs it: one that revoked at its
 * issuer OUTSIDE CredentialMutation's afterCommit path -- its own remote call,
 * its own bookkeeping -- and therefore knows about a failure that no scope on
 * the caller's side can observe, however the caller collects.
 *
 * Which makes it the only shape that can tell a caller who MERGES the driver's
 * report from one who REPLACES it with its own. Both look identical everywhere
 * else, because a scope around the factor call already sees every mutation the
 * factor makes through CredentialMutation.
 */
final class SelfReportingFactor implements Factor
{
    /** @param list<array{0: string, 1: string}> $failures issuer key, token key */
    public function __construct(
        private readonly Factor $inner,
        private readonly array $failures,
    ) {}

    /** @param array<string, mixed> $data */
    public function enroll(int $userId, array $data): EnrollmentResult
    {
        $enrollment = $this->inner->enroll($userId, $data);

        $report = new CredentialDriverFailureReport;

        foreach ($this->failures as [$issuerKey, $tokenKey]) {
            $report->record($issuerKey, $tokenKey);
        }

        /*
         * The inner result's own report is deliberately NOT forwarded, because a
         * factor cannot forward it -- the property is private and only the identity
         * list is readable. That is the constraint CompanionRetiringFactor documents,
         * and it is why this fixture's own report is the whole of what it can offer.
         */
        return new EnrollmentResult($enrollment->credentials, $enrollment->secrets, $report);
    }

    public function revoke(AuthCredential $credential): void
    {
        $this->inner->revoke($credential);
    }

    public function id(): string
    {
        return $this->inner->id();
    }

    public function kind(): FactorKind
    {
        return $this->inner->kind();
    }

    public function strength(): FactorStrength
    {
        return $this->inner->strength();
    }

    public function maxActiveCredentials(): ?int
    {
        return $this->inner->maxActiveCredentials();
    }

    public function challenge(ChallengeRequest $request): ?AuthChallenge
    {
        return $this->inner->challenge($request);
    }

    public function verify(VerificationRequest $request): FactorResult
    {
        return $this->inner->verify($request);
    }
}
