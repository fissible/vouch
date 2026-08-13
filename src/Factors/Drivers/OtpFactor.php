<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors\Drivers;

use Fissible\Vouch\Attempts\Mutations\ConsumeChallenge;
use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Contracts\OtpDelivery;
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
 * OtpDelivery seam for transport.
 */
abstract readonly class OtpFactor implements Factor
{
    public function __construct(
        protected EnrollmentGuard $guard,
        protected ClockInterface $clock,
        protected OtpDelivery $delivery,
        protected int $length = 6,
        protected int $ttlSeconds = 120,
    ) {}

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

        // No one-time secrets: an OTP credential holds nothing to show.
        return new EnrollmentResult([$credential]);
    }

    public function challenge(ChallengeRequest $request): ?AuthChallenge
    {
        $credential = $request->credential ?? $this->resolveSoleCredential($request);
        $identifier = AuthIdentifier::query()->findOrFail($credential->identifier_id);

        $code = $this->generateCode();
        $expiresAt = $this->clock->now()->modify(sprintf('+%d seconds', $this->ttlSeconds));

        /*
         * The challenge row is written BEFORE delivery. If delivery throws, the
         * user gets a code that was never sent and the challenge expires
         * harmlessly; the reverse order risks a delivered code with no row to
         * verify it against, which locks the user out of a factor they hold.
         *
         * GuardsChallengeTarget validates credential_id here — active, same
         * user, identifier-linked — so an unusable target cannot be persisted.
         */
        $challenge = AuthChallenge::create([
            'attempt_id' => $request->attempt->id,
            'credential_id' => $credential->id,
            'factor_type' => $this->id(),
            'code_hash' => Hash::make($code),
            'bound_ip' => $request->clientIp,
            'bound_user_agent' => $request->clientUserAgent,
            'expires_at' => $expiresAt,
        ]);

        $this->delivery->deliver($identifier, $code, $expiresAt);

        return $challenge;
    }

    public function verify(VerificationRequest $request): FactorResult
    {
        $submitted = $request->string('code');

        if ($submitted === null) {
            return FactorResult::failed(FactorFailure::Malformed);
        }

        $challenge = $request->challenge ?? $this->resolveLatestChallenge($request);

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

        if (! Hash::check($submitted, $challenge->code_hash)) {
            return FactorResult::failed(FactorFailure::Mismatch);
        }

        $credentialId = $challenge->credential_id;

        if ($credentialId === null) {
            // GuardsChallengeTarget makes this unreachable for OTP; failing
            // closed rather than inventing a credential id keeps it that way.
            return FactorResult::failed(FactorFailure::NoCredential);
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
        $credential->update(['disabled_at' => $this->clock->now()]);
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
            $code .= (string) random_int(0, 9);
        }

        return $code;
    }
}
