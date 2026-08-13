<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors\Drivers;

use Fissible\Vouch\Attempts\Mutations\DisableCredential;
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
use Fissible\Vouch\Secrets\OneTimeSecret;
use Illuminate\Support\Facades\Hash;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;

/**
 * Single-use recovery codes: one credential row per code.
 *
 * Carries FactorStrength::Recovery, which SatisfiabilityEvaluator filters out of
 * both satisfiability and assurance facts. A recovery code therefore cannot
 * satisfy a policy BY CONSTRUCTION rather than by driver discipline — the guard
 * lives in kernel code that is mutation-tested.
 *
 * Verification compares against every active code in turn, which is up to ten
 * hash comparisons per attempt. That is a real cost and a real amplification
 * factor; rate limiting is 2.3's, and this driver deliberately does not invent
 * its own.
 */
final readonly class RecoveryCodeFactor implements Factor
{
    /** Crockford-style alphabet: no I, L, O, U, so a transcribed code is unambiguous. */
    private const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

    /**
     * Validated once here rather than trusted from config, in the same spirit as
     * TotpFactor's guards. A length of 0 is not a weak code, it is NO code:
     * generateCode() returns '', Hash::make('') is stored, and password_verify()
     * returns true for an empty submission — every user with a generated set
     * would be satisfiable by submitting nothing. A count of 0 is quieter but
     * just as wrong: enroll() would return an empty set and report success.
     */
    public function __construct(
        private EnrollmentGuard $guard,
        private ClockInterface $clock,
        private int $count = 10,
        private int $length = 10,
    ) {
        if ($this->count < 1) {
            throw new InvalidArgumentException(sprintf(
                'RecoveryCodeFactor requires a count of at least 1: config "vouch.recovery.count" '
                . '(env VOUCH_RECOVERY_CODE_COUNT) resolved to %d. That config reads '
                . '`(int) env(...)`, so a set-but-blank VOUCH_RECOVERY_CODE_COUNT= arrives as 0 '
                . 'rather than the default.',
                $this->count,
            ));
        }

        if ($this->length < 1) {
            throw new InvalidArgumentException(sprintf(
                'RecoveryCodeFactor requires a length of at least 1: config '
                . '"vouch.recovery.length" (env VOUCH_RECOVERY_CODE_LENGTH) resolved to %d. That '
                . 'config reads `(int) env(...)`, so a set-but-blank VOUCH_RECOVERY_CODE_LENGTH= '
                . 'arrives as 0 rather than the default — which would generate empty codes that '
                . 'any empty submission matches.',
                $this->length,
            ));
        }
    }

    public function id(): string
    {
        return 'recovery_code';
    }

    public function kind(): FactorKind
    {
        return FactorKind::Possession;
    }

    public function strength(): FactorStrength
    {
        return FactorStrength::Recovery;
    }

    /**
     * Always $this->count (typed int, never null): PHPStan level 9 flags `?int`
     * here as an unused nullable branch. Covariant with the interface's `?int`.
     */
    public function maxActiveCredentials(): int
    {
        return $this->count;
    }

    /**
     * Generate a fresh set, retiring every prior code.
     *
     * Enrollment and regeneration are the same operation: disabling first makes
     * it idempotent whether or not codes already exist, and satisfies the
     * promise that regenerating invalidates all prior codes. Both halves run
     * inside one serialized closure, so a concurrent pair cannot interleave into
     * a mixed set.
     *
     * @param  array<string, mixed>  $data
     */
    public function enroll(int $userId, array $data): EnrollmentResult
    {
        /** @var array{codes: list<string>, credentials: list<AuthCredential>} $generated */
        $generated = $this->guard->serialize(
            $userId,
            $this->id(),
            $this->maxActiveCredentials(),
            function () use ($userId): array {
                AuthCredential::query()
                    ->where('user_id', $userId)
                    ->where('type', $this->id())
                    ->whereNull('disabled_at')
                    ->update(['disabled_at' => $this->clock->now()]);

                $codes = [];
                $credentials = [];

                for ($i = 0; $i < $this->count; $i++) {
                    $code = $this->generateCode();
                    $codes[] = $code;
                    $credentials[] = AuthCredential::create([
                        'user_id' => $userId,
                        'type' => $this->id(),
                        'secret' => Hash::make($code),
                        'strength' => $this->strength()->name,
                    ]);
                }

                return ['codes' => $codes, 'credentials' => $credentials];
            },
        );

        return new EnrollmentResult(
            $generated['credentials'],
            array_map(static fn (string $code): OneTimeSecret => new OneTimeSecret($code), $generated['codes']),
        );
    }

    public function challenge(ChallengeRequest $request): ?AuthChallenge
    {
        return null;
    }

    public function verify(VerificationRequest $request): FactorResult
    {
        $submitted = $request->string('code');

        if ($submitted === null) {
            return FactorResult::failed(FactorFailure::Malformed);
        }

        $normalised = strtoupper(str_replace([' ', '-'], '', $submitted));

        /*
         * Checked AFTER normalisation, and before any query: '  - - ' normalises
         * to '' just as '' does, and password_verify('', ...) against a hash of
         * '' returns true — so an empty code is malformed input, never a code
         * attempt. Rejecting here also denies an attacker ten free bcrypt
         * comparisons per empty submission.
         */
        if ($normalised === '') {
            return FactorResult::failed(FactorFailure::Malformed);
        }

        $userId = $request->attempt->user_id;

        if ($userId === null) {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        $candidates = AuthCredential::query()
            ->where('user_id', $userId)
            ->where('type', $this->id())
            ->whereNull('disabled_at')
            ->get();

        if ($candidates->isEmpty()) {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        foreach ($candidates as $credential) {
            if (! is_string($credential->secret) || ! Hash::check($normalised, $credential->secret)) {
                continue;
            }

            /*
             * Return the mutation; do NOT disable here. A code burned by the
             * driver stays burned when the transition then fails, which is a
             * denial of service against a legitimate user.
             */
            return FactorResult::satisfied(
                new SatisfiedFactor(
                    factorId: $this->id(),
                    credentialId: (string) $credential->id,
                    kind: $this->kind(),
                    strength: $this->strength(),
                    isMultiFactor: false,
                    userVerified: false,
                    phishingResistant: false,
                    authenticatorId: null,
                    satisfiedAt: $this->clock->now(),
                ),
                new DisableCredential($credential->id),
            );
        }

        return FactorResult::failed(FactorFailure::Mismatch);
    }

    public function revoke(AuthCredential $credential): void
    {
        $credential->update(['disabled_at' => $this->clock->now()]);
    }

    /**
     * random_int() is a CSPRNG. rand() and mt_rand() are predictable from
     * observed output, and a predictable recovery code is a bypass of every
     * other factor on the account.
     */
    private function generateCode(): string
    {
        $alphabet = self::ALPHABET;
        $max = strlen($alphabet) - 1;
        $code = '';

        for ($i = 0; $i < $this->length; $i++) {
            $code .= $alphabet[random_int(0, $max)];
        }

        return $code;
    }
}
