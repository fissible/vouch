<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

use Fissible\Vouch\Throttle\ChallengeAttemptDecision;
use Fissible\Vouch\Throttle\IdentifierThrottle;
use Fissible\Vouch\Throttle\IssuancePermission;
use Fissible\Vouch\Throttle\SharedThrottle;
use Fissible\Vouch\Throttle\ThrottleSubject;

/**
 * Authentication-specific persistence boundary for Phase 2.3b controls.
 *
 * Every subject has already passed canonicalization and HMAC derivation. No
 * operation accepts a raw identifier, IP, tenant, or resolved user, and no
 * operation returns a digest or supports candidate lookup.
 *
 * Identifier and shared writes are deliberately separate calls: the caller
 * commits authoritative identifier state first, then advisory state in a
 * separate transaction whose verified contention may fail open for that one
 * dimension. The interface makes the required ordering visible rather than
 * hiding it in a bulk recordFailure() call.
 */
interface AuthThrottleStore
{
    public function preflightIdentifier(ThrottleSubject $identifier): IdentifierThrottle;

    public function preflightShared(ThrottleSubject $subject): SharedThrottle;

    public function recordIdentifierFailure(ThrottleSubject $identifier): IdentifierThrottle;

    public function recordRecoveryFailure(ThrottleSubject $recovery): SharedThrottle;

    public function recordIpFailure(
        ThrottleSubject $ip,
        ThrottleSubject $ipIdentifier,
    ): SharedThrottle;

    public function recordSharedFailure(ThrottleSubject $subject): SharedThrottle;

    public function resetIdentifier(ThrottleSubject $identifier): void;

    public function recordChallengeFailure(int $challengeId): ChallengeAttemptDecision;

    public function permitIssuance(ThrottleSubject $issuance): IssuancePermission;
}
