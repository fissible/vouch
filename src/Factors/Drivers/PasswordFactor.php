<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors\Drivers;

use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\EnrollmentResult;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Support\Facades\Hash;
use Psr\Clock\ClockInterface;

/**
 * The knowledge factor.
 *
 * Rehash-on-verify is deliberately absent in v1, and that is a
 * SECURITY-MAINTENANCE LIMITATION rather than a deferred optimisation: raising
 * the bcrypt cost, or moving to a stronger algorithm, reaches new and changed
 * passwords only. A user who never changes theirs keeps the hash they enrolled
 * with indefinitely. It was left out because it is a credential write on the
 * verification path, and threading it through the single-use mutation machinery
 * would blur a boundary in the slice that establishes it. Any operator raising
 * the work factor needs to know it will not propagate.
 */
final readonly class PasswordFactor implements Factor
{
    public function __construct(
        private EnrollmentGuard $guard,
        private ClockInterface $clock,
    ) {}

    public function id(): string
    {
        return 'password';
    }

    public function kind(): FactorKind
    {
        return FactorKind::Knowledge;
    }

    public function strength(): FactorStrength
    {
        return FactorStrength::Knowledge;
    }

    /**
     * Always 1: PHPStan level 9 flags `?int` here as an unused nullable branch,
     * since the body never returns null. Covariant with the interface's `?int`.
     */
    public function maxActiveCredentials(): int
    {
        return 1;
    }

    /**
     * @param  array{password?: mixed, replace?: mixed}  $data
     */
    public function enroll(int $userId, array $data): EnrollmentResult
    {
        $password = $data['password'] ?? null;

        if (! is_string($password) || $password === '') {
            throw new \InvalidArgumentException('PasswordFactor::enroll() requires a non-empty "password" string.');
        }

        $replace = ($data['replace'] ?? false) === true;

        $credential = $this->guard->serialize(
            $userId,
            $this->id(),
            $this->maxActiveCredentials(),
            function () use ($userId, $password, $replace): AuthCredential {
                if ($replace) {
                    /*
                     * Disable and create inside ONE serialized closure, so the
                     * guard's post-condition sees the net result. This is why
                     * cardinality is checked after the write rather than before.
                     */
                    AuthCredential::query()
                        ->where('user_id', $userId)
                        ->where('type', $this->id())
                        ->whereNull('disabled_at')
                        ->update(['disabled_at' => $this->clock->now()]);
                }

                return AuthCredential::create([
                    'user_id' => $userId,
                    'type' => $this->id(),
                    'secret' => Hash::make($password),
                    'strength' => $this->strength()->name,
                ]);
            },
        );

        // No one-time secrets: the user already knows their password.
        return new EnrollmentResult([$credential]);
    }

    public function challenge(ChallengeRequest $request): ?AuthChallenge
    {
        return null;
    }

    public function verify(VerificationRequest $request): FactorResult
    {
        $submitted = $request->string('password');

        /*
         * Empty is malformed, not a mismatch. enroll() refuses an empty password,
         * so no credential here should hash one — but password_verify('', ...)
         * against a hash of '' returns TRUE, so if one ever did, an empty
         * submission would satisfy the factor. Refusing before the comparison
         * makes that unreachable instead of merely unlikely, and matches TOTP,
         * recovery-code and OTP, which all report '' as Malformed.
         */
        if ($submitted === null || $submitted === '') {
            return FactorResult::failed(FactorFailure::Malformed);
        }

        $userId = $request->attempt->user_id;

        if ($userId === null) {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        $credential = AuthCredential::query()
            ->where('user_id', $userId)
            ->where('type', $this->id())
            ->whereNull('disabled_at')
            ->first();

        if (! $credential instanceof AuthCredential || ! is_string($credential->secret)) {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        if (! Hash::check($submitted, $credential->secret)) {
            return FactorResult::failed(FactorFailure::Mismatch);
        }

        /*
         * No mutations. A password is not single-use, and returning one here
         * would put a write on the verification path for no security reason.
         */
        return FactorResult::satisfied(new SatisfiedFactor(
            factorId: $this->id(),
            credentialId: (string) $credential->id,
            kind: $this->kind(),
            strength: $this->strength(),
            isMultiFactor: false,
            userVerified: false,
            phishingResistant: false,
            authenticatorId: null,
            satisfiedAt: $this->clock->now(),
        ));
    }

    public function revoke(AuthCredential $credential): void
    {
        $credential->update(['disabled_at' => $this->clock->now()]);
    }
}
