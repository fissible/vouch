<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\EnrollmentResult;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;

/**
 * One authentication factor: how it enrolls, challenges, and verifies.
 *
 * Two rules bind every implementation:
 *
 *  - **Drivers validate; they never evaluate policy.** Report what happened and
 *    let the kernel judge satisfiability.
 *  - **Drivers never write single-use state.** Return SingleUseMutation objects
 *    on the FactorResult and let the store execute them inside its transaction.
 *    A code burned outside that transaction stays burned when the transition
 *    then fails, which is a denial of service against a legitimate user.
 *
 * Takes `int $userId` rather than a user model: vouch never references the
 * host's authenticatable class, and every foreign key in the schema is a plain
 * integer.
 */
interface Factor
{
    /** Registry key. Matches auth_credentials.type. */
    public function id(): string;

    public function kind(): FactorKind;

    public function strength(): FactorStrength;

    /**
     * 1, a finite number, or null for unbounded.
     *
     * Counted over ACTIVE credentials only — disabled_at IS NULL. A revoked TOTP
     * must never block enrolling its replacement; that would be a self-inflicted
     * lockout. Enforcement is EnrollmentGuard's, not the driver's: a property is
     * not an invariant until the write path is atomic.
     */
    public function maxActiveCredentials(): ?int;

    /**
     * @param  array<string, mixed>  $data
     */
    public function enroll(int $userId, array $data): EnrollmentResult;

    /** Null when the factor needs no challenge — password, TOTP, recovery code. */
    public function challenge(ChallengeRequest $request): ?AuthChallenge;

    public function verify(VerificationRequest $request): FactorResult;

    /**
     * Known limitation: a revoke() that performs TWO credential mutations in
     * sequence currently has only the first one's issuer-revocation failures
     * reported back to the caller. The credential writes and proof withdrawal
     * both happen; it is the reporting that stops short, so a caller can be
     * told cleanup was clean while a token from the second mutation is still
     * live at its issuer. No shipped factor does this -- password, TOTP,
     * recovery code and the OTP drivers each perform one. Tracked separately.
     */
    public function revoke(AuthCredential $credential): void;
}
