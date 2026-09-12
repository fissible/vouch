<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Factors\EnrollmentResult;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;

/**
 * Wraps a real factor and keeps the EnrollmentResult it produced.
 *
 * Lets a test assert that self-service returned the DRIVER'S OneTimeSecret
 * instances rather than revealing them and wrapping fresh ones. The difference
 * is invisible to any assertion about the strings: a service that revealed a
 * secret, logged it, and re-wrapped the value would satisfy every containment
 * check on the rendered result while having already leaked it.
 */
final class CapturingFactor implements Factor
{
    public ?EnrollmentResult $captured = null;

    /** @param callable():void|null $onEnroll Runs before the inner enrollment. */
    public function __construct(
        private readonly Factor $inner,
        private readonly mixed $onEnroll = null,
    ) {}

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

    public function challenge(\Fissible\Vouch\Factors\ChallengeRequest $request): ?\Fissible\Vouch\Models\AuthChallenge
    {
        return $this->inner->challenge($request);
    }

    public function revoke(\Fissible\Vouch\Models\AuthCredential $credential): void
    {
        $this->inner->revoke($credential);
    }

    /** @param array<string, mixed> $data */
    public function enroll(int $userId, array $data): EnrollmentResult
    {
        if ($this->onEnroll !== null) {
            ($this->onEnroll)();
        }

        return $this->captured = $this->inner->enroll($userId, $data);
    }

    public function verify(VerificationRequest $request): FactorResult
    {
        return $this->inner->verify($request);
    }
}
