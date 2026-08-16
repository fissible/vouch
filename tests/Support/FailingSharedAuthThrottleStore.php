<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Throttle\ChallengeAttemptDecision;
use Fissible\Vouch\Throttle\IdentifierThrottle;
use Fissible\Vouch\Throttle\IssuancePermission;
use Fissible\Vouch\Throttle\SharedThrottle;
use Fissible\Vouch\Throttle\ThrottleSubject;
use RuntimeException;

/** Delegates real persistence except for one nominated advisory boundary. */
final readonly class FailingSharedAuthThrottleStore implements AuthThrottleStore
{
    public function __construct(private AuthThrottleStore $inner) {}

    public function preflightIdentifier(ThrottleSubject $identifier): IdentifierThrottle
    {
        return $this->inner->preflightIdentifier($identifier);
    }

    public function preflightShared(ThrottleSubject $subject): SharedThrottle
    {
        return $this->inner->preflightShared($subject);
    }

    public function recordIdentifierFailure(ThrottleSubject $identifier): IdentifierThrottle
    {
        return $this->inner->recordIdentifierFailure($identifier);
    }

    public function recordRecoveryFailure(ThrottleSubject $recovery): SharedThrottle
    {
        return $this->inner->recordRecoveryFailure($recovery);
    }

    public function recordIpFailure(
        ThrottleSubject $ip,
        ThrottleSubject $ipIdentifier,
    ): SharedThrottle {
        throw new RuntimeException('Forced advisory IP persistence failure.');
    }

    public function recordSharedFailure(ThrottleSubject $subject): SharedThrottle
    {
        return $this->inner->recordSharedFailure($subject);
    }

    public function resetIdentifier(ThrottleSubject $identifier): void
    {
        $this->inner->resetIdentifier($identifier);
    }

    public function recordChallengeFailure(int $challengeId): ChallengeAttemptDecision
    {
        return $this->inner->recordChallengeFailure($challengeId);
    }

    public function permitIssuance(ThrottleSubject $issuance): IssuancePermission
    {
        return $this->inner->permitIssuance($issuance);
    }
}
