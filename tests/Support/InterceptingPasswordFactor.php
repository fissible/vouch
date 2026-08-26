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
 * Wraps the real password factor so a test can observe or disturb the exact
 * moment of credential mutation.
 *
 * The ordering contract can only be proven by observing state BETWEEN the two
 * commits. Asserting after the call is not enough: the broken order
 * "mutate, fail, then revoke" satisfies every post-call assertion. The
 * before-callback records what was true on ENTRY to enroll(), which is the only
 * point where the two orderings differ.
 *
 * Substituted by contextual binding rather than FactorRegistry::register(),
 * which is deliberately write-once so a permissive driver cannot displace a
 * restrictive one. That protection is not weakened to make a test observable.
 */
final class InterceptingPasswordFactor implements Factor
{
    public int $enrollCalls = 0;

    /** State observed at the moment enroll() was entered. */
    public mixed $observed = null;

    public function __construct(
        private readonly Factor $inner,
        private readonly ?Closure $before = null,
        private readonly bool $throw = false,
    ) {}

    public function enroll(int $userId, array $data): EnrollmentResult
    {
        $this->enrollCalls++;

        if ($this->before instanceof Closure) {
            $this->observed = ($this->before)($userId);
        }

        if ($this->throw) {
            throw new RuntimeException('Credential mutation failed after revocation committed.');
        }

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

    public function revoke(AuthCredential $credential): void
    {
        $this->inner->revoke($credential);
    }
}
