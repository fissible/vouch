<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use DateTimeImmutable;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Kernel\Enumeration\Outcome;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Kernel\Policy\PolicyParser;
use Fissible\Vouch\Kernel\Satisfiability\SatisfiabilityEvaluator;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Psr\Clock\ClockInterface;

/**
 * Drives an authentication attempt.
 *
 * Four things this class never does, each of which has a home elsewhere:
 *
 *  - It never re-derives transition legality. It calls AttemptStore, which asks
 *    the kernel's TransitionRules. Re-deriving would be a second implementation
 *    of a rule that is already mutation-tested.
 *  - It never writes single-use state. Driver mutations go to transition() and
 *    are applied inside the transaction that advances the attempt.
 *  - It never touches a session, request or response. Nothing HTTP-shaped
 *    crosses this boundary, which is what lets one core drive both the JSON
 *    surface and Phase 3's adapters.
 *  - It never constructs an error message. ScreenBuilder does, through
 *    ErrorShaper.
 */
final readonly class AuthFlow
{
    public function __construct(
        private AttemptStore $store,
        private FactorRegistry $registry,
        private ScreenBuilder $screens,
        private SatisfiabilityEvaluator $evaluator,
        private AssuranceVocabulary $vocabulary,
        private ClockInterface $clock,
        private int $attemptTtlSeconds,
    ) {}

    public function advance(FlowRequest $request): FlowResult
    {
        if ($request->handle === null) {
            return $this->begin($request);
        }

        $attempt = AuthAttempt::query()->where('handle', $request->handle)->first();

        /*
         * A missing attempt and a context mismatch are the same shaped refusal,
         * and neither echoes a handle. Distinguishing them would tell a handle
         * holder whether the handle is real, which is an oracle over handles.
         */
        if (! $attempt instanceof AuthAttempt || $attempt->bound_context !== $request->boundContext) {
            return new Continuing(
                $this->screens->refused(AuthStep::Identify, Outcome::CredentialRejected, $this->posture(null)),
                null,
            );
        }

        return match ($attempt->state) {
            AttemptState::Initiated => $this->identify($attempt, $request),
            default => $this->verify($attempt, $request),
        };
    }

    /**
     * Create the attempt. This is the only place an attempt is born.
     *
     * The handle is 32 bytes of CSPRNG output, hex-encoded to 64 characters to
     * match auth_attempts.handle. random_bytes(), never mt_rand() — a guessable
     * handle plus a matching bound context would be an attempt takeover.
     *
     * bound_context is REQUIRED here. An attempt cannot exist unbound: the
     * handle identifies it and must not also authorize it.
     */
    private function begin(FlowRequest $request): FlowResult
    {
        $attempt = AuthAttempt::create([
            'handle' => bin2hex(random_bytes(32)),
            'state' => AttemptState::Initiated,
            'version' => 1,
            'bound_context' => $request->boundContext,
            'expires_at' => $this->clock->now()->modify(sprintf('+%d seconds', $this->attemptTtlSeconds)),
        ]);

        return new Continuing($this->screens->identify($this->posture(null)), $attempt->handle);
    }

    private function identify(AuthAttempt $attempt, FlowRequest $request): FlowResult
    {
        $posture = $this->posture($attempt->tenant_id);
        $value = $request->string('identifier');

        if ($value === null || $value === '') {
            return new Continuing(
                $this->screens->refused(AuthStep::Identify, Outcome::CredentialRejected, $posture),
                $attempt->handle,
            );
        }

        $identifier = AuthIdentifier::query()->where('value', $value)->whereNotNull('verified_at')->first();

        /*
         * An unknown identifier still advances the attempt and still offers a
         * challenge screen. Refusing here would make the identify step itself an
         * account-existence oracle regardless of what the message says: the flow
         * would visibly stop for unknown identifiers and continue for known
         * ones. The shaped screen carries whatever posture permits.
         */
        $userId = $identifier?->user_id;

        $attempt->update(['identifier' => $value, 'user_id' => $userId]);

        /*
         * Two transitions, because the kernel's machine has no Identified ->
         * Authenticated edge: Initiated -> Identified -> FactorPending ->
         * FactorSatisfied -> Authenticated. Offering a challenge IS entering
         * FactorPending, so the two happen together here rather than leaving
         * the attempt in a state the next request would have to repair.
         */
        if ($this->store->transition($attempt, AttemptState::Identified) !== TransitionOutcome::Succeeded
            || $this->store->transition($attempt->refresh(), AttemptState::FactorPending) !== TransitionOutcome::Succeeded) {
            return new Continuing(
                $this->screens->refused(AuthStep::Identify, Outcome::CredentialRejected, $posture),
                $attempt->handle,
            );
        }

        return new Continuing(
            $this->screens->challenge($this->defaultFactorFor($userId), $posture),
            $attempt->handle,
        );
    }

    private function verify(AuthAttempt $attempt, FlowRequest $request): FlowResult
    {
        $posture = $this->posture($attempt->tenant_id);
        $factorId = $request->action === 'recover' ? 'recovery_code' : $this->defaultFactorFor($attempt->user_id);

        $refusal = fn (): FlowResult => new Continuing(
            $this->screens->refused(AuthStep::Challenge, Outcome::CredentialRejected, $posture, $factorId),
            $attempt->handle,
        );

        $userId = $attempt->user_id;

        if (! $this->registry->has($factorId) || $userId === null) {
            return $refusal();
        }

        $result = $this->registry->get($factorId)->verify(new VerificationRequest(
            attempt: $attempt,
            input: $request->input,
            clientIp: $request->clientIp,
            clientUserAgent: $request->clientUserAgent,
        ));

        if (! $result->isSatisfied()) {
            return $refusal();
        }

        $satisfied = [...$this->existingFactors($attempt), $result->factor];
        $isRecovery = $result->factor->strength === FactorStrength::Recovery;

        /*
         * Driver mutations ride on THIS transition — the one that records the
         * factor as satisfied — because that is the transaction whose failure
         * must also roll back a burned code. Any later transition carries none.
         */
        if ($this->store->transition($attempt, AttemptState::FactorSatisfied, ...$result->mutations) !== TransitionOutcome::Succeeded) {
            return $refusal();
        }

        $attempt->refresh()->update(['satisfied_factors' => $this->encode($satisfied)]);

        if ($isRecovery) {
            return new RecoveryGraceStarted(
                userId: $userId,
                boundContext: $request->boundContext,
                screen: $this->screens->challenge('password', $posture),
            );
        }

        /*
         * Policy decides whether more evidence is needed. Asking the kernel's
         * evaluator, never re-deriving satisfiability here.
         */
        if ($this->targetState($attempt, $satisfied) !== AttemptState::Authenticated) {
            // Back to FactorPending: another factor is being offered.
            $this->store->transition($attempt->refresh(), AttemptState::FactorPending);

            return new Continuing(
                $this->screens->challenge($this->defaultFactorFor($userId), $posture),
                $attempt->handle,
            );
        }

        if ($this->store->transition($attempt->refresh(), AttemptState::Authenticated) !== TransitionOutcome::Succeeded) {
            return $refusal();
        }

        $facts = AssuranceFacts::fromFactors($satisfied);

        return new Authenticated(
            new AuthSuccess(
                userId: $userId,
                factors: $satisfied,
                facts: $facts,
                acr: $this->vocabulary->name($facts),
                boundContext: $request->boundContext,
            ),
            $this->screens->challenge($this->defaultFactorFor($userId), $posture),
        );
    }

    /**
     * Whether the policy is satisfied by the evidence gathered so far.
     *
     * Asks the kernel's evaluator. This method must never decide satisfiability
     * itself — that logic is mutation-tested in Phase 1, and a second copy here
     * would be the one that drifts.
     *
     * @param  list<SatisfiedFactor>  $satisfied
     */
    private function targetState(AuthAttempt $attempt, array $satisfied): AttemptState
    {
        $policy = $this->policyFor($attempt->tenant_id);

        if ($policy === null) {
            return AttemptState::FactorSatisfied;
        }

        return $this->evaluator->evaluate((new PolicyParser())->parse($policy->document), $satisfied)->satisfied
            ? AttemptState::Authenticated
            : AttemptState::FactorSatisfied;
    }

    private function policyFor(?string $tenantId): ?AuthPolicy
    {
        return AuthPolicy::query()
            ->where('scope', 'login')
            ->where(fn ($query) => $query->where('tenant_id', $tenantId)->orWhereNull('tenant_id'))
            ->orderByRaw('tenant_id is null')
            ->first();
    }

    private function posture(?string $tenantId): EnumerationPosture
    {
        $posture = $this->policyFor($tenantId)?->posture;

        return $posture === 'strict' ? EnumerationPosture::Strict : EnumerationPosture::Friendly;
    }

    /**
     * The factor to offer next.
     *
     * Recovery is never offered as a default: it cannot satisfy a policy, so
     * presenting it as the primary path would lead a user into a screen that
     * cannot complete their login.
     */
    private function defaultFactorFor(?int $userId): string
    {
        if ($userId === null) {
            return 'password';
        }

        $type = AuthCredential::query()
            ->where('user_id', $userId)
            ->whereNull('disabled_at')
            ->where('type', '!=', 'recovery_code')
            ->value('type');

        return is_string($type) && $this->registry->has($type) ? $type : 'password';
    }

    /**
     * Rehydrate the evidence already gathered on this attempt.
     *
     * @return list<SatisfiedFactor>
     */
    private function existingFactors(AuthAttempt $attempt): array
    {
        $stored = $attempt->satisfied_factors ?? [];
        $factors = [];

        foreach ($stored as $row) {
            /*
             * Guards rather than casts. This data round-trips through JSON, so
             * every field is mixed on the way back; casting mixed would let a
             * malformed row become a SatisfiedFactor carrying empty strings,
             * which the kernel would then evaluate as real evidence.
             *
             * No is_array($row) check: AuthAttempt declares
             * list<array<string, mixed>>, and encode() below is the only writer.
             * The per-field guards are what protect the contents.
             */
            if (! is_string($row['factor_id'] ?? null)
                || ! is_string($row['credential_id'] ?? null)
                || ! is_string($row['kind'] ?? null)
                || ! is_int($row['strength'] ?? null)
                || ! is_string($row['satisfied_at'] ?? null)) {
                continue;
            }

            $kind = FactorKind::tryFrom($row['kind']);
            $strength = FactorStrength::tryFrom($row['strength']);
            $authenticatorId = $row['authenticator_id'] ?? null;

            if ($kind === null || $strength === null) {
                continue;
            }

            $factors[] = new SatisfiedFactor(
                factorId: $row['factor_id'],
                credentialId: $row['credential_id'],
                kind: $kind,
                strength: $strength,
                isMultiFactor: ($row['is_multi_factor'] ?? false) === true,
                userVerified: ($row['user_verified'] ?? false) === true,
                phishingResistant: ($row['phishing_resistant'] ?? false) === true,
                authenticatorId: is_string($authenticatorId) ? $authenticatorId : null,
                satisfiedAt: new DateTimeImmutable($row['satisfied_at']),
            );
        }

        return $factors;
    }

    /**
     * @param  list<SatisfiedFactor>  $satisfied
     * @return list<array<string, mixed>>
     */
    private function encode(array $satisfied): array
    {
        return array_map(static fn (SatisfiedFactor $factor): array => [
            'factor_id' => $factor->factorId,
            'credential_id' => $factor->credentialId,
            'kind' => $factor->kind->value,
            'strength' => $factor->strength->value,
            'is_multi_factor' => $factor->isMultiFactor,
            'user_verified' => $factor->userVerified,
            'phishing_resistant' => $factor->phishingResistant,
            'authenticator_id' => $factor->authenticatorId,
            'satisfied_at' => $factor->satisfiedAt->format(DATE_ATOM),
        ], $satisfied);
    }
}
