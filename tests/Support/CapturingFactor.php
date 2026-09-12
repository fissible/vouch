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

    /**
     * @param  callable():void|null  $onEnroll       Runs BEFORE the inner enrollment.
     * @param  callable():void|null  $onEnrolled     Runs AFTER it, with material already minted.
     *
     * The two are different failures and a test should say which it means: one
     * is an enrollment that never happened, the other is an operation that
     * fails once secrets exist and must not hand them back anyway.
     */
    public function __construct(
        private readonly Factor $inner,
        private readonly mixed $onEnroll = null,
        private readonly mixed $onEnrolled = null,
    ) {}

    /**
     * The enrollment the inner driver produced.
     *
     * Reading the nullable property directly pushes the "was it ever enrolled?"
     * question to every call site, where a missed null reads as "no secrets"
     * rather than "the double was never invoked" -- the two findings a test
     * here most needs to tell apart.
     */
    public function enrollment(): EnrollmentResult
    {
        return $this->captured ?? throw new \RuntimeException('The factor was never enrolled.');
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

        $this->captured = $this->inner->enroll($userId, $data);

        if ($this->onEnrolled !== null) {
            ($this->onEnrolled)();
        }

        return $this->captured;
    }

    public function verify(VerificationRequest $request): FactorResult
    {
        return $this->inner->verify($request);
    }
}
