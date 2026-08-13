<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors\Drivers;

use Fissible\Vouch\Attempts\Mutations\AdvanceCredentialTimestep;
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
use InvalidArgumentException;
use OTPHP\TOTP;
use Psr\Clock\ClockInterface;

/**
 * RFC 6238 time-based one-time passwords, over spomky-labs/otphp.
 *
 * DELIBERATELY DOES NOT USE otphp's $leeway PARAMETER. TOTP::verify() returns
 * bool and, with a leeway, checks three timestamps internally — so the matched
 * timestep is unrecoverable. Amendment B needs that step to record it, and a
 * replay guard that cannot name the step it consumed permits exactly the replay
 * RFC 6238 §5.2 forbids. This driver iterates candidate steps and verifies each
 * exactly, at $step * $period with a null leeway.
 *
 * The driver's own watermark check is a fast path, not the guarantee. Two
 * concurrent submissions can both read the old watermark before either writes;
 * the store's guarded `last_used_timestep < :step` update is what makes the
 * guard atomic.
 */
final readonly class TotpFactor implements Factor
{
    /**
     * Validated once here rather than trusted from config: otphp's setIssuer()
     * requires a non-empty issuer and the timestep arithmetic below requires a
     * positive period, so a driver that only *hoped* config was well-formed
     * would fail confusingly deep inside otphp instead of at construction.
     *
     * No PHPDoc type narrowing (non-empty-string, positive-int) is needed on
     * these promoted properties: PHPStan derives it itself, since every
     * control-flow path out of a `readonly` property's constructor either
     * throws or leaves the property satisfying these `if` guards.
     */
    public function __construct(
        private EnrollmentGuard $guard,
        private ClockInterface $clock,
        private string $issuer = 'Vouch',
        private int $period = 30,
        private int $digits = 6,
        private int $window = 1,
    ) {
        if ($this->issuer === '') {
            throw new InvalidArgumentException('TotpFactor requires a non-empty issuer.');
        }

        if ($this->period < 1) {
            throw new InvalidArgumentException('TotpFactor requires a period of at least 1 second.');
        }

        if ($this->digits < 1) {
            throw new InvalidArgumentException('TotpFactor requires at least 1 digit.');
        }

        if ($this->window < 0) {
            throw new InvalidArgumentException('TotpFactor requires a non-negative window.');
        }
    }

    public function id(): string
    {
        return 'totp';
    }

    public function kind(): FactorKind
    {
        return FactorKind::Possession;
    }

    public function strength(): FactorStrength
    {
        return FactorStrength::Possession;
    }

    public function maxActiveCredentials(): int
    {
        return 1;
    }

    /**
     * @param  array{label?: mixed, replace?: mixed}  $data
     */
    public function enroll(int $userId, array $data): EnrollmentResult
    {
        $label = $data['label'] ?? null;

        if (! is_string($label) || $label === '') {
            throw new InvalidArgumentException(
                'TotpFactor::enroll() requires a non-empty "label" string — it is what the '
                . 'authenticator app shows next to the code.',
            );
        }

        $replace = ($data['replace'] ?? false) === true;

        $totp = TOTP::generate($this->clock);
        $totp->setPeriod($this->period);
        $totp->setDigits($this->digits);
        $totp->setLabel($label);
        // The constructor refuses an empty issuer, and PHPStan derives
        // non-empty-string for this readonly property from that guard.
        $totp->setIssuer($this->issuer);

        $secret = $totp->getSecret();

        /** @var AuthCredential $credential */
        $credential = $this->guard->serialize(
            $userId,
            $this->id(),
            $this->maxActiveCredentials(),
            function () use ($userId, $secret, $replace): AuthCredential {
                if ($replace) {
                    AuthCredential::query()
                        ->where('user_id', $userId)
                        ->where('type', $this->id())
                        ->whereNull('disabled_at')
                        ->update(['disabled_at' => $this->clock->now()]);
                }

                return AuthCredential::create([
                    'user_id' => $userId,
                    'type' => $this->id(),
                    // `encrypted` cast: the seed is a credential, not a label.
                    'secret' => $secret,
                    'strength' => $this->strength()->name,
                ]);
            },
        );

        return new EnrollmentResult(
            [$credential],
            [new OneTimeSecret($totp->getProvisioningUri())],
        );
    }

    public function challenge(ChallengeRequest $request): ?AuthChallenge
    {
        return null;
    }

    public function verify(VerificationRequest $request): FactorResult
    {
        $submitted = $request->string('code');

        // Empty string is malformed, not a mismatch: TOTP::verify() requires a
        // non-empty otp, and an empty submission was never a real code attempt.
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

        $secret = $credential?->secret;

        if (! $credential instanceof AuthCredential || ! is_string($secret) || $secret === '') {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        $matched = $this->matchTimestep($secret, $submitted);

        if ($matched === null) {
            return FactorResult::failed(FactorFailure::Mismatch);
        }

        /*
         * Fast path only. The authoritative guard is the store's
         * `last_used_timestep IS NULL OR < :step` predicate, which is atomic;
         * this check exists so an obvious replay costs no transaction.
         */
        if ($credential->last_used_timestep !== null && $matched <= $credential->last_used_timestep) {
            return FactorResult::failed(FactorFailure::Consumed);
        }

        return FactorResult::satisfied(
            new SatisfiedFactor(
                factorId: $this->id(),
                credentialId: (string) $credential->id,
                kind: $this->kind(),
                strength: $this->strength(),
                // A TOTP seed is exportable software state: single-factor, no
                // user verification, and not phishing-resistant. AAL3 requires a
                // non-exportable hardware-held key, which this is not.
                isMultiFactor: false,
                userVerified: false,
                phishingResistant: false,
                authenticatorId: null,
                satisfiedAt: $this->clock->now(),
            ),
            new AdvanceCredentialTimestep($credential->id, $matched),
        );
    }

    public function revoke(AuthCredential $credential): void
    {
        $credential->update(['disabled_at' => $this->clock->now()]);
    }

    /**
     * Find which timestep the submitted code belongs to, or null.
     *
     * Candidates run newest-first so a code valid in more than one step — which
     * cannot happen with distinct secrets but is cheap to be deterministic
     * about — resolves to the highest step, advancing the watermark furthest.
     *
     * Every comparison goes through otphp's compareOTP(), which is hash_equals.
     *
     * @param  non-empty-string  $secret
     * @param  non-empty-string  $submitted
     */
    private function matchTimestep(string $secret, string $submitted): ?int
    {
        $totp = TOTP::createFromSecret($secret, $this->clock);
        $totp->setPeriod($this->period);
        $totp->setDigits($this->digits);

        $currentStep = intdiv($this->clock->now()->getTimestamp(), $this->period);

        for ($offset = $this->window; $offset >= -$this->window; $offset--) {
            $step = $currentStep + $offset;

            if ($step < 0) {
                continue;
            }

            // Null leeway: an EXACT comparison at this timestamp, so a match
            // identifies the step unambiguously. `$step * $this->period` is
            // provably int<0, max> here — verify()'s $timestamp parameter —
            // because $step is non-negative (the guard above) and the
            // constructor refuses a non-positive period, so PHPStan derives
            // positive-int for this readonly property.
            if ($totp->verify($submitted, $step * $this->period, null)) {
                return $step;
            }
        }

        return null;
    }
}
