<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors\Drivers;

use Fissible\Vouch\Attempts\Mutations\ConsumeChallenge;
use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Credentials\CredentialMutation;
use Fissible\Vouch\Contracts\RandomSource;
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
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Notifications\OtpChallengeOutbox;
use Fissible\Vouch\Support\SystemRandomSource;
use Fissible\Vouch\Throttle\ChallengeAttemptDecision;
use Illuminate\Support\Facades\Hash;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;

/**
 * Shared behaviour for the email and SMS one-time-password drivers.
 *
 * No library sits underneath these. `spatie/laravel-one-time-passwords` was
 * evaluated and rejected: it ships its own table and requires a trait on the
 * host's authenticatable model, which breaks both vouch's rule against touching
 * the host user class and the rule that the STORE owns every single-use
 * mutation — it cannot, for a table it does not control.
 *
 * So: random_int() for generation, the host-configured Hash driver for storage
 * and constant-time comparison, vouch's own auth_challenges for state, and an
 * encrypted outbox for asynchronous transport.
 */
abstract readonly class OtpFactor implements Factor
{
    /**
     * Validated once here rather than trusted from config, in the same spirit as
     * TotpFactor's guards. A length of 0 is not a weak code, it is NO code:
     * generateCode() returns '', Hash::make('') is stored on the challenge, and
     * password_verify('', ...) returns true — so every delivered challenge would
     * be satisfiable by submitting nothing. Unlike recovery codes, OTP carries
     * PossessionWeak and IS counted towards satisfiability, so that would be a
     * live policy bypass rather than a contained one.
     */
    public function __construct(
        protected EnrollmentGuard $guard,
        protected ClockInterface $clock,
        protected OtpChallengeOutbox $outbox,
        protected AuthThrottleStore $throttle,
        protected int $length = 6,
        protected int $ttlSeconds = 120,
        // See RecoveryCodeFactor: injected so the digit range is testable at
        // its boundaries rather than only in aggregate.
        protected RandomSource $random = new SystemRandomSource(),
    ) {
        if ($this->length < 1) {
            throw new InvalidArgumentException(sprintf(
                '%s requires a code length of at least 1: config "vouch.otp.length" (env '
                . 'VOUCH_OTP_LENGTH) resolved to %d. That config reads `(int) env(...)`, so a '
                . 'set-but-blank VOUCH_OTP_LENGTH= arrives as 0 rather than the default — which '
                . 'would deliver empty codes that any empty submission matches.',
                static::class,
                $this->length,
            ));
        }

        if ($this->ttlSeconds < 1) {
            throw new InvalidArgumentException(sprintf(
                '%s requires a ttl of at least 1 second: config "vouch.otp.ttl_seconds" (env '
                . 'VOUCH_OTP_TTL) resolved to %d. That config reads `(int) env(...)`, so a '
                . 'set-but-blank VOUCH_OTP_TTL= arrives as 0 rather than the default — which '
                . 'would expire every code at the instant it is delivered.',
                static::class,
                $this->ttlSeconds,
            ));
        }
    }

    /** The auth_identifiers.type this driver delivers to. */
    abstract protected function identifierType(): string;

    public function kind(): FactorKind
    {
        return FactorKind::Possession;
    }

    public function strength(): FactorStrength
    {
        return FactorStrength::PossessionWeak;
    }

    /**
     * Unbounded: naturally limited by how many identifiers the user has verified,
     * and the unique (user_id, type, identifier_id) index stops duplicates per
     * address.
     */
    public function maxActiveCredentials(): ?int
    {
        return null;
    }

    /**
     * Enroll — or RE-ENABLE — this user's credential for one verified identifier.
     *
     * Re-enabling rather than inserting is required because the unique index
     * counts disabled rows and a partial index is not portable across the three
     * engines. It preserves the credential ID, so auth_token_assurances
     * references and kernel distinctness stay coherent.
     *
     * This asymmetry is honest ONLY because OTP credentials are secretless: the
     * code lives in auth_challenges, so re-enrollment genuinely is re-enabling.
     * Password and TOTP re-enrollment must still create a fresh row.
     *
     * @param  array{identifier_id?: mixed}  $data
     */
    public function enroll(int $userId, array $data): EnrollmentResult
    {
        $identifierId = $data['identifier_id'] ?? null;

        if (! is_int($identifierId)) {
            throw new InvalidArgumentException(sprintf(
                '%s::enroll() requires an integer "identifier_id".',
                static::class,
            ));
        }

        $identifier = AuthIdentifier::query()->find($identifierId);

        if (! $identifier instanceof AuthIdentifier) {
            throw new InvalidArgumentException(sprintf('Identifier %d does not exist.', $identifierId));
        }

        if ($identifier->type !== $this->identifierType()) {
            throw new InvalidArgumentException(sprintf(
                '%s delivers to "%s" identifiers, but identifier %d is a "%s". Delivering an '
                . 'SMS code to an email address, or the reverse, would send it nowhere useful.',
                static::class,
                $this->identifierType(),
                $identifierId,
                $identifier->type,
            ));
        }

        /*
         * Same-user and verified are NOT re-checked here. GuardsIdentifierLinkage
         * enforces both on the model write path, so they hold however the row is
         * created — including by code that never read this method.
         */
        $credential = null;
        $write = function () use ($userId, $identifierId, &$credential): void {
            $credential = $this->guard->serialize(
            $userId,
            $this->id(),
            $this->maxActiveCredentials(),
            function () use ($userId, $identifierId): AuthCredential {
                $existing = AuthCredential::query()
                    ->where('user_id', $userId)
                    ->where('type', $this->id())
                    ->where('identifier_id', $identifierId)
                    ->first();

                if ($existing instanceof AuthCredential) {
                    // Preserve the ID. A new row would orphan every existing
                    // token-assurance reference to this credential.
                    $existing->update(['disabled_at' => null]);

                    return $existing->refresh();
                }

                return AuthCredential::create([
                    'user_id' => $userId,
                    'type' => $this->id(),
                    'identifier_id' => $identifierId,
                    'secret' => null,
                    'strength' => $this->strength()->name,
                ]);
            },
            );
        };
        $this->mutation()->additive(SubjectKey::forConfiguredUser($userId), $write);

        if (! $credential instanceof AuthCredential) {
            throw new \LogicException('OTP enrollment did not create a credential.');
        }

        // No one-time secrets: an OTP credential holds nothing to show.
        return new EnrollmentResult([$credential]);
    }

    public function challenge(ChallengeRequest $request): ?AuthChallenge
    {
        $this->outbox->assertReady();

        if ($request->decoy) {
            if ($request->credential !== null) {
                throw new InvalidArgumentException(
                    'A decoy OTP challenge cannot name a real credential target.',
                );
            }

            $credential = null;
            $identifier = null;
        } else {
            $credential = $request->credential ?? $this->resolveSoleCredential($request);

            /*
             * resolveSoleCredential() filters on type and disabled_at; a CALLER-
             * supplied credential has been through neither, and GuardsChallengeTarget
             * checks existence, active, same-user and identifier linkage but never
             * that the credential's type matches the challenge's factor_type. Without
             * this, EmailOtpFactor could be handed an sms_otp credential, deliver to
             * its phone identifier, and write factor_type='email_otp' — after which
             * verify() satisfies email_otp and a policy that specifically requires
             * email is satisfied by SMS.
             */
            if ($credential->type !== $this->id()) {
                throw new InvalidArgumentException(sprintf(
                    'Credential %d is a "%s", but %s issues "%s" challenges. Delivering against '
                    . 'another factor\'s credential would let the challenge claim a factor type it '
                    . 'never exercised.',
                    $credential->id,
                    $credential->type,
                    static::class,
                    $this->id(),
                ));
            }

            if ($credential->disabled_at !== null) {
                throw new InvalidArgumentException(sprintf(
                    'Credential %d is disabled and cannot be sent an %s code.',
                    $credential->id,
                    $this->id(),
                ));
            }

            $identifier = AuthIdentifier::query()->findOrFail($credential->identifier_id);
        }

        $code = $this->generateCode();

        /*
         * Challenge and encrypted delivery payload commit atomically. Provider
         * I/O happens only in the queued worker, and retries reload this exact
         * code rather than minting a replacement that would no longer match the
         * challenge hash.
         */
        return $this->outbox->issue(
            new ChallengeRequest(
                attempt: $request->attempt,
                credential: $credential,
                clientIp: $request->clientIp,
                clientUserAgent: $request->clientUserAgent,
                decoy: $request->decoy,
                reusePending: $request->reusePending,
            ),
            $this->id(),
            $code,
            $this->ttlSeconds,
            $identifier,
        );
    }

    public function verify(VerificationRequest $request): FactorResult
    {
        $submitted = $request->string('code');

        /*
         * Empty is malformed, not a mismatch: password_verify('', ...) against a
         * hash of '' returns TRUE, so an empty submission must never reach the
         * comparison. The constructor now refuses a zero length, which is the
         * only way an empty code could have been hashed onto a challenge; this is
         * the second of the two locks, and matches TOTP and recovery code.
         */
        if ($submitted === null || $submitted === '') {
            return FactorResult::failed(FactorFailure::Malformed);
        }

        $challenge = $request->challenge ?? $this->resolveLatestChallenge($request);

        if (! $challenge instanceof AuthChallenge) {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        /*
         * A caller-supplied Eloquent model is only a locator, never authority.
         * It may predate another request consuming or invalidating the row. A
         * stale object must not make verify() claim satisfaction and defer the
         * refusal to the later ConsumeChallenge mutation.
         */
        $challenge = AuthChallenge::query()->find($challenge->id);

        if (! $challenge instanceof AuthChallenge) {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        if ($challenge->attempt_id !== $request->attempt->id || $challenge->factor_type !== $this->id()) {
            return FactorResult::failed(FactorFailure::BindingMismatch);
        }

        if ($challenge->consumed_at !== null) {
            return FactorResult::failed(FactorFailure::Consumed);
        }

        if ($challenge->expires_at->getTimestamp() <= $this->clock->now()->getTimestamp()) {
            return FactorResult::failed(FactorFailure::Expired);
        }

        /*
         * Binding is checked BEFORE the code comparison, and this is the whole
         * reason VerificationRequest carries client context: bound_ip and
         * bound_user_agent are written at delivery, and a driver that could not
         * read them would leave them stored and never evaluated.
         */
        if (! $this->bindingMatches($challenge, $request)) {
            return FactorResult::failed(FactorFailure::BindingMismatch);
        }

        $credentialId = $challenge->credential_id;

        if ($credentialId === null) {
            // GuardsChallengeTarget makes this unreachable for OTP; failing
            // closed rather than inventing a credential id keeps it that way.
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        /*
         * Re-read the credential AT VERIFY TIME. GuardsChallengeTarget hooks
         * `creating` only, so its disabled_at check fires once, at delivery, and
         * never again — revoking a credential mid-TTL would otherwise leave its
         * outstanding code verifying happily for the rest of the TTL, and return
         * a SatisfiedFactor naming a revoked credential. Password, TOTP and
         * recovery code all filter whereNull('disabled_at') at verify time; this
         * is OTP paying the same rent, before the comparison so a revoked
         * credential costs no bcrypt.
         */
        $credential = AuthCredential::query()
            ->whereKey($credentialId)
            ->where('type', $this->id())
            ->whereNull('disabled_at')
            ->first();

        if (! $credential instanceof AuthCredential) {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        if (! Hash::check($submitted, $challenge->code_hash)) {
            $decision = $this->throttle->recordChallengeFailure($challenge->id);

            if ($decision === ChallengeAttemptDecision::Consumed) {
                return FactorResult::failed(FactorFailure::Consumed);
            }

            if ($decision === ChallengeAttemptDecision::Expired) {
                return FactorResult::failed(FactorFailure::Expired);
            }

            if ($decision === ChallengeAttemptDecision::Unavailable) {
                return FactorResult::failed(FactorFailure::NoCredential);
            }

            return FactorResult::failed(FactorFailure::Mismatch);
        }

        return FactorResult::satisfied(
            new SatisfiedFactor(
                factorId: $this->id(),
                // Read from the challenge, never inferred: this is the record of
                // what was actually delivered.
                credentialId: (string) $credentialId,
                kind: $this->kind(),
                strength: $this->strength(),
                isMultiFactor: false,
                userVerified: false,
                phishingResistant: false,
                authenticatorId: null,
                satisfiedAt: $this->clock->now(),
            ),
            new ConsumeChallenge($challenge->id, $request->attempt->id),
        );
    }

    public function revoke(AuthCredential $credential): void
    {
        $this->mutation()->revoking(SubjectKey::forConfiguredUser($credential->user_id), [(string) $credential->id], function () use ($credential): void {
            $credential->update(['disabled_at' => $this->clock->now()]);
        });
    }

    private function mutation(): CredentialMutation
    {
        return app()->makeWith(CredentialMutation::class, ['connection' => $this->guard->connection()]);
    }

    /**
     * A null bound value means the challenge was issued without that context and
     * cannot constrain anything. A non-null one must match exactly.
     */
    private function bindingMatches(AuthChallenge $challenge, VerificationRequest $request): bool
    {
        if ($challenge->bound_ip !== null && $challenge->bound_ip !== $request->clientIp) {
            return false;
        }

        return ! ($challenge->bound_user_agent !== null
            && $challenge->bound_user_agent !== $request->clientUserAgent);
    }

    private function resolveSoleCredential(ChallengeRequest $request): AuthCredential
    {
        $userId = $request->attempt->user_id;

        if ($userId === null) {
            throw new InvalidArgumentException(
                'Cannot issue an OTP challenge for an attempt with no identified user.',
            );
        }

        $candidates = AuthCredential::query()
            ->where('user_id', $userId)
            ->where('type', $this->id())
            ->whereNull('disabled_at')
            ->get();

        if ($candidates->count() !== 1) {
            throw new InvalidArgumentException(sprintf(
                'ChallengeRequest named no credential and user %d has %d active %s credentials. '
                . 'Choosing one silently would deliver a code to an address the user did not pick.',
                $userId,
                $candidates->count(),
                $this->id(),
            ));
        }

        $sole = $candidates->first();

        if (! $sole instanceof AuthCredential) {
            // Unreachable: the count check above already guarantees exactly
            // one. Failing closed here rather than trusting Collection::first()
            // keeps that guarantee load-bearing instead of assumed.
            throw new InvalidArgumentException('Expected exactly one active OTP credential.');
        }

        return $sole;
    }

    private function resolveLatestChallenge(VerificationRequest $request): ?AuthChallenge
    {
        return AuthChallenge::query()
            ->where('attempt_id', $request->attempt->id)
            ->where('factor_type', $this->id())
            ->whereNull('consumed_at')
            ->latest('id')
            ->first();
    }

    /**
     * random_int() is a CSPRNG. A six-digit code is only about 20 bits, so a
     * predictable generator would make it trivially guessable rather than merely
     * weak — which is why the TTL is short and rate limiting arrives in 2.3.
     */
    private function generateCode(): string
    {
        $code = '';

        for ($i = 0; $i < $this->length; $i++) {
            $code .= (string) $this->random->int(0, 9);
        }

        return $code;
    }
}
