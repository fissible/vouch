<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Throttle\ChallengeAttemptDecision;
use Fissible\Vouch\Throttle\IdentifierThrottle;
use Fissible\Vouch\Throttle\IssuancePermission;
use Fissible\Vouch\Throttle\SharedThrottle;
use Fissible\Vouch\Throttle\ThrottleSubject;

/** Recording contract implementation reused by the Task 12 flow-order proof. */
final class RecordingAuthThrottleStore implements AuthThrottleStore
{
    /** @var list<array{operation: string, subjects: list<ThrottleSubject|int>}> */
    public array $calls = [];

    public function preflightIdentifier(ThrottleSubject $identifier): IdentifierThrottle
    {
        $this->record(__FUNCTION__, $identifier);

        return IdentifierThrottle::permitted(10);
    }

    public function preflightShared(ThrottleSubject $subject): SharedThrottle
    {
        $this->record(__FUNCTION__, $subject);

        return SharedThrottle::permitted();
    }

    public function recordIdentifierFailure(ThrottleSubject $identifier): IdentifierThrottle
    {
        $this->record(__FUNCTION__, $identifier);

        return IdentifierThrottle::permitted(9);
    }

    public function recordRecoveryFailure(ThrottleSubject $recovery): SharedThrottle
    {
        $this->record(__FUNCTION__, $recovery);

        return SharedThrottle::permitted();
    }

    public function recordIpFailure(
        ThrottleSubject $ip,
        ThrottleSubject $ipIdentifier,
    ): SharedThrottle {
        $this->record(__FUNCTION__, $ip, $ipIdentifier);

        return SharedThrottle::observed();
    }

    public function recordSharedFailure(ThrottleSubject $subject): SharedThrottle
    {
        $this->record(__FUNCTION__, $subject);

        return SharedThrottle::observed();
    }

    public function resetIdentifier(ThrottleSubject $identifier): void
    {
        $this->record(__FUNCTION__, $identifier);
    }

    public function recordChallengeFailure(int $challengeId): ChallengeAttemptDecision
    {
        $this->record(__FUNCTION__, $challengeId);

        return ChallengeAttemptDecision::Remaining;
    }

    public function permitIssuance(ThrottleSubject $issuance): IssuancePermission
    {
        $this->record(__FUNCTION__, $issuance);

        return IssuancePermission::Permitted;
    }

    /** @param ThrottleSubject|int ...$subjects */
    private function record(string $operation, ThrottleSubject|int ...$subjects): void
    {
        $this->calls[] = [
            'operation' => $operation,
            'subjects' => array_values($subjects),
        ];
    }
}
