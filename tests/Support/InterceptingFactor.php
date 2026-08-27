<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Closure;
use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\EnrollmentResult;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;
use RuntimeException;

/**
 * Wraps any factor so a test can observe or disturb the moment of credential
 * mutation, for both enroll() and revoke().
 *
 * Substituted by building a fresh FactorRegistry rather than mutating the
 * container's singleton: registration is write-once by design, so a permissive
 * driver cannot displace a restrictive one, and that guard is not weakened to
 * make a test observable.
 */
final class InterceptingFactor implements Factor
{
    public int $revokeCalls = 0;

    public int $enrollCalls = 0;

    /** State observed on entry to the intercepted call. */
    public mixed $observed = null;

    public function __construct(
        private readonly Factor $inner,
        private readonly ?Closure $beforeRevoke = null,
        private readonly bool $throwOnRevoke = false,
    ) {}

    public function revoke(AuthCredential $credential): void
    {
        $this->revokeCalls++;

        if ($this->beforeRevoke instanceof Closure) {
            $this->observed = ($this->beforeRevoke)($credential);
        }

        if ($this->throwOnRevoke) {
            throw new RuntimeException('Credential mutation failed after revocation committed.');
        }

        $this->inner->revoke($credential);
    }

    public function enroll(int $userId, array $data): EnrollmentResult
    {
        $this->enrollCalls++;

        return $this->inner->enroll($userId, $data);
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
