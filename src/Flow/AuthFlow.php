<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use DateTimeImmutable;
use Exception;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Contracts\TenantResolver;
use Fissible\Vouch\Factors\ChallengeIssuanceIntent;
use Fissible\Vouch\Factors\ChallengeIssuanceTicket;
use Fissible\Vouch\Factors\ChallengeIssuer;
use Fissible\Vouch\Factors\FactorFailure;
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
use Fissible\Vouch\Throttle\IdentifierThrottle;
use Fissible\Vouch\Throttle\IssuancePermission;
use Fissible\Vouch\Throttle\SharedThrottle;
use Fissible\Vouch\Throttle\ThrottleDecision;
use Fissible\Vouch\Throttle\ThrottleKey;
use Fissible\Vouch\Throttle\ThrottleSubject;
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
        private AuthThrottleStore $throttles,
        private ThrottleKey $throttleKey,
        private TenantResolver $tenants,
        private FactorRegistry $registry,
        private ChallengeIssuer $issuer,
        private ScreenBuilder $screens,
        private SatisfiabilityEvaluator $evaluator,
        private AssuranceVocabulary $vocabulary,
        private VerificationEqualizer $equalizer,
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
            'tenant_id' => $this->tenants->currentTenantId(),
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

        $requestedFactor = $request->string('factor');
        $factorId = is_string($requestedFactor)
            && $requestedFactor !== 'recovery_code'
            && $this->registry->has($requestedFactor)
                ? $requestedFactor
                : 'password';

        // Constructed and charged before the identifier query below. Whether
        // that query later resolves cannot alter the issuance state channel.
        $issuance = $this->issuer->supports($factorId)
            ? $this->issuer->permit($this->issuanceIntent(
                $attempt,
                $request,
                $value,
                $factorId,
                'identify',
            ))
            : null;

        if ($issuance?->permission === IssuancePermission::Refused) {
            return new Continuing(
                $this->screens->refused(
                    AuthStep::Identify,
                    Outcome::CredentialRejected,
                    $posture,
                ),
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

        $attempt->refresh();

        if ($issuance instanceof ChallengeIssuanceTicket) {
            $this->issuer->complete($issuance, $attempt);
        }

        return new Continuing($this->screens->challenge($factorId, $posture), $attempt->handle);
    }

    private function verify(AuthAttempt $attempt, FlowRequest $request): FlowResult
    {
        $posture = $this->posture($attempt->tenant_id);
        $submittedIdentifier = $attempt->identifier;

        if (! is_string($submittedIdentifier) || $submittedIdentifier === '') {
            $this->equalizer->equalize($posture);

            return $this->refusal($attempt, $posture, 'password');
        }

        $preflight = $this->preflightThrottle($attempt, $request, $submittedIdentifier);

        if ($preflight !== null) {
            // Do not derive presentation from the resolved user on a preflight
            // refusal. The retry state is target-independent, and the screen is too.
            return $this->refusal($attempt, $posture, 'password', $preflight);
        }

        if ($attempt->state === AttemptState::FactorPending
            && in_array($request->action, ['challenge', 'resend'], true)) {
            $requested = $request->string('factor');

            if (is_string($requested) && $this->issuer->supports($requested)) {
                $ticket = $this->issuer->permit($this->issuanceIntent(
                    $attempt,
                    $request,
                    $submittedIdentifier,
                    $requested,
                    $request->action,
                ));

                if ($ticket->permission === IssuancePermission::Refused) {
                    return $this->refusal($attempt, $posture, $requested);
                }

                $this->issuer->complete($ticket, $attempt);

                return new Continuing(
                    $this->screens->challenge($requested, $posture),
                    $attempt->handle,
                );
            }
        }

        $offered = $this->offeredFactorsFor($attempt);
        $factorId = $this->selectFactor($attempt, $request, $offered);

        /*
         * The refusal screen names a factor the server offers, never the one the
         * client asked for. Echoing an unoffered id back would make the refusal
         * screen itself a probe: submit a guess, read it in the response, and
         * learn which drivers the server recognises.
         */
        $presented = $offered[0] ?? 'password';

        $refusal = fn (IdentifierThrottle|SharedThrottle|null $throttle = null): FlowResult =>
            $this->refusal($attempt, $posture, $presented, $throttle);

        $userId = $attempt->user_id;

        if ($factorId === null || ! $this->registry->has($factorId) || $userId === null) {
            /*
             * No user means no credential to verify, so nothing would hash --
             * and under strict posture that speed difference IS the account
             * existence oracle. Pay the same cost before refusing.
             */
            $this->equalizer->equalize($posture);

            return $refusal($this->recordThrottleFailure($attempt, $request, $submittedIdentifier));
        }

        $result = $this->registry->get($factorId)->verify(new VerificationRequest(
            attempt: $attempt,
            input: $request->input,
            clientIp: $request->clientIp,
            clientUserAgent: $request->clientUserAgent,
        ));

        if (! $result->isSatisfied()) {
            /*
             * A driver reporting NoCredential also did no hashing -- a user who
             * exists but has no credential of this type. Same leak, same fix.
             */
            if ($result->failure === FactorFailure::NoCredential) {
                $this->equalizer->equalize($posture);
            }

            return $refusal($this->recordThrottleFailure($attempt, $request, $submittedIdentifier));
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

            $attempt->refresh();
            $next = $this->offeredFactorsFor($attempt)[0] ?? $this->defaultFactorFor($userId);

            if ($this->issuer->supports($next)) {
                $ticket = $this->issuer->permit($this->issuanceIntent(
                    $attempt,
                    $request,
                    $submittedIdentifier,
                    $next,
                    'continue',
                ));

                if ($ticket->permission === IssuancePermission::Refused) {
                    return $refusal();
                }

                $this->issuer->complete($ticket, $attempt);
            }

            return new Continuing(
                $this->screens->challenge($next, $posture),
                $attempt->handle,
            );
        }

        if ($this->store->transition($attempt->refresh(), AttemptState::Authenticated) !== TransitionOutcome::Succeeded) {
            return $refusal();
        }

        // A satisfied factor is not authentication. Reset only after the final
        // compare-and-swap commits, or the first factor in an all_of policy would
        // refill the budget for attacking the second.
        $this->throttles->resetIdentifier(
            $this->identifierSubject($attempt, $submittedIdentifier),
        );

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

    private function refusal(
        AuthAttempt $attempt,
        EnumerationPosture $posture,
        string $presented,
        IdentifierThrottle|SharedThrottle|null $throttle = null,
    ): FlowResult {
        $outcome = $throttle instanceof IdentifierThrottle
            && $throttle->decision === ThrottleDecision::Locked
                ? Outcome::Locked
                : Outcome::CredentialRejected;

        return new Continuing(
            $this->screens->refused(
                AuthStep::Challenge,
                $outcome,
                $posture,
                $presented,
                $throttle,
            ),
            $attempt->handle,
        );
    }

    private function preflightThrottle(
        AuthAttempt $attempt,
        FlowRequest $request,
        string $submittedIdentifier,
    ): IdentifierThrottle|SharedThrottle|null {
        if ($request->action === 'recover') {
            $recovery = $this->throttles->preflightShared(
                $this->throttleKey->recovery($submittedIdentifier, $attempt->tenant_id),
            );

            if ($recovery->decision === ThrottleDecision::BackedOff) {
                return $recovery;
            }
        } else {
            $identifier = $this->throttles->preflightIdentifier(
                $this->identifierSubject($attempt, $submittedIdentifier),
            );

            if (in_array($identifier->decision, [
                ThrottleDecision::BackedOff,
                ThrottleDecision::Locked,
            ], true)) {
                return $identifier;
            }
        }

        foreach ($this->sharedSubjects($attempt, $request) as $subject) {
            $shared = $this->throttles->preflightShared($subject);

            if ($shared->decision === ThrottleDecision::BackedOff) {
                return $shared;
            }
        }

        return null;
    }

    private function recordThrottleFailure(
        AuthAttempt $attempt,
        FlowRequest $request,
        string $submittedIdentifier,
    ): IdentifierThrottle|SharedThrottle|null {
        $identifier = null;
        $recovery = null;

        // The authoritative subject commits before any advisory shared work. A
        // crash may under-count breadth, but can never erase this failure.
        if ($request->action === 'recover') {
            $recovery = $this->throttles->recordRecoveryFailure(
                $this->throttleKey->recovery($submittedIdentifier, $attempt->tenant_id),
            );
        } else {
            $identifier = $this->throttles->recordIdentifierFailure(
                $this->identifierSubject($attempt, $submittedIdentifier),
            );
        }

        $sharedBackoff = null;
        $ip = $this->throttleKey->ip($request->clientIp, $attempt->tenant_id);
        $ipIdentifier = $this->throttleKey->ipIdentifier(
            $request->clientIp,
            $submittedIdentifier,
            $attempt->tenant_id,
        );

        if ($ip !== null && $ipIdentifier !== null) {
            $state = $this->throttles->recordIpFailure($ip, $ipIdentifier);

            if ($state->decision === ThrottleDecision::BackedOff) {
                $sharedBackoff = $state;
            }
        }

        foreach ([
            $this->throttleKey->tenant($attempt->tenant_id),
            $this->throttleKey->global(),
        ] as $subject) {
            $state = $this->throttles->recordSharedFailure($subject);

            if ($sharedBackoff === null && $state->decision === ThrottleDecision::BackedOff) {
                $sharedBackoff = $state;
            }
        }

        if ($identifier !== null && in_array($identifier->decision, [
            ThrottleDecision::BackedOff,
            ThrottleDecision::Locked,
        ], true)) {
            return $identifier;
        }

        if ($recovery?->decision === ThrottleDecision::BackedOff) {
            return $recovery;
        }

        return $sharedBackoff ?? $identifier;
    }

    /** @return list<ThrottleSubject> */
    private function sharedSubjects(AuthAttempt $attempt, FlowRequest $request): array
    {
        $subjects = [];
        $ip = $this->throttleKey->ip($request->clientIp, $attempt->tenant_id);

        if ($ip !== null) {
            $subjects[] = $ip;
        }

        $subjects[] = $this->throttleKey->tenant($attempt->tenant_id);
        $subjects[] = $this->throttleKey->global();

        return $subjects;
    }

    private function identifierSubject(
        AuthAttempt $attempt,
        string $submittedIdentifier,
    ): ThrottleSubject {
        return $this->throttleKey->identifier($submittedIdentifier, $attempt->tenant_id);
    }

    private function issuanceIntent(
        AuthAttempt $attempt,
        FlowRequest $request,
        string $submittedIdentifier,
        string $factorId,
        string $action,
    ): ChallengeIssuanceIntent {
        return new ChallengeIssuanceIntent(
            attemptId: $attempt->id,
            submittedIdentifier: $submittedIdentifier,
            factorId: $factorId,
            action: $action,
            tenantId: $attempt->tenant_id,
            clientIp: $request->clientIp,
            clientUserAgent: $request->clientUserAgent,
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
    /**
     * The factors this attempt may be advanced with RIGHT NOW.
     *
     * Server-side, and deliberately narrower than "everything registered": a
     * factor is offered only if the user holds an active credential of that
     * type, a driver is registered for it, and it has not already been
     * satisfied on this attempt.
     *
     * Excluding already-satisfied factors is what makes an all_of policy
     * progress. Without it the default is recomputed as the same first
     * credential on every step, so a two-factor login re-challenges the factor
     * it just accepted and can never reach its second one.
     *
     * recovery_code is absent by design. Recovery is its own action with its own
     * outcome — a constrained capability rather than a login — and letting it be
     * selected here would route it through the ordinary satisfy path.
     *
     * @return list<string>
     */
    private function offeredFactorsFor(AuthAttempt $attempt): array
    {
        $userId = $attempt->user_id;

        if ($userId === null) {
            return [];
        }

        $satisfied = array_map(
            static fn (SatisfiedFactor $factor): string => $factor->factorId,
            $this->existingFactors($attempt),
        );

        $offered = [];

        foreach (AuthCredential::query()
            ->where('user_id', $userId)
            ->whereNull('disabled_at')
            ->pluck('type') as $type) {
            if (! is_string($type)
                || $type === 'recovery_code'
                || ! $this->registry->has($type)
                || in_array($type, $satisfied, true)
                || in_array($type, $offered, true)) {
                continue;
            }

            $offered[] = $type;
        }

        return $offered;
    }

    /**
     * Which factor this submission is verified against.
     *
     * The client MAY choose, but only from what the server currently offers. A
     * named factor is honoured when it is in that set and refused otherwise —
     * it is never used to look up a registry driver or a credential directly,
     * so a client cannot reach a factor the policy has not put in front of it,
     * re-submit one it has already satisfied, or name recovery_code to slip
     * recovery evidence through the ordinary path.
     *
     * @param  list<string>  $offered
     */
    private function selectFactor(AuthAttempt $attempt, FlowRequest $request, array $offered): ?string
    {
        if ($request->action === 'recover') {
            return 'recovery_code';
        }

        $requested = $request->string('factor');

        if ($requested !== null && $requested !== '') {
            return in_array($requested, $offered, true) ? $requested : null;
        }

        return $offered[0] ?? null;
    }

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

            /*
             * is_string() above proves the field is a string, not that it is a
             * PARSABLE one. new DateTimeImmutable('not-a-date') throws, and this
             * runs on a public code path over data from a database column -- so
             * an unparsable timestamp was a request-triggerable 500 rather than a
             * rejected row.
             *
             * Skipping matches every other guard here: a row we cannot read is a
             * row we do not trust, and it costs exactly itself.
             */
            try {
                $satisfiedAt = new DateTimeImmutable($row['satisfied_at']);
            } catch (Exception) {
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
                satisfiedAt: $satisfiedAt,
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
