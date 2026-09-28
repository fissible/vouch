<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Closure;
use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Credentials\CredentialMutation;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\EnrollmentResult;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Tokens\SubjectKey;

/**
 * A host factor whose revoke() performs more than one credential mutation.
 *
 * `Factor::revoke()` does not restrict a driver to a single mutation, and a
 * factor that retires a companion credential alongside the requested one is an
 * ordinary shape for one: a hardware token registered as two credentials, a
 * paired device, a legacy row kept beside its replacement.
 *
 * The mutations here are SEQUENTIAL -- each finishes before the next begins --
 * which is what separates this from an observer that starts a mutation part way
 * through somebody else's. Both look like "a second mutation on this connection"
 * from the outside, and only one of them is the caller's own work.
 *
 * Substituted by building a fresh FactorRegistry rather than by mutating the
 * container's singleton, as InterceptingFactor is: registration is write-once by
 * design and that guard is not weakened to make a test observable.
 */
final class CompanionRevokingFactor implements Factor
{
    public int $revokeCalls = 0;

    /**
     * Companion ids in the order their mutations were entered.
     *
     * @var list<int>
     */
    public array $mutated = [];

    /**
     * @param  list<array{id: int, before: ?Closure}>  $companions  each retired in
     *         its own mutation, with `before` run immediately before it -- the hook
     *         a test uses to create a proof only that mutation can withdraw.
     */
    public function __construct(
        private readonly Factor $inner,
        private readonly array $companions,
        private readonly int $userId = 1,
    ) {}

    public function revoke(AuthCredential $credential): void
    {
        $this->revokeCalls++;

        $this->inner->revoke($credential);

        foreach ($this->companions as $companion) {
            if ($companion['before'] instanceof Closure) {
                ($companion['before'])();
            }

            $this->mutated[] = $companion['id'];

            $id = $companion['id'];

            /*
             * A real mutation rather than a bare update: the point of the shape is
             * that each companion goes through the same invalidation, proof
             * withdrawal and driver-revocation path the requested credential does.
             */
            app(CredentialMutation::class)->revoking(
                SubjectKey::forConfiguredUser($this->userId),
                [(string) $id],
                static function () use ($id): null {
                    /*
                     * The model instance, as every shipped driver does, not a mass
                     * update on the query builder. A builder update fires no Eloquent
                     * events, which would make these companion mutations quieter than
                     * a real factor's -- and would mean this fixture could never
                     * exercise a companion mutation that is itself observed, which is
                     * exactly the mechanism the contamination tests use.
                     */
                    AuthCredential::query()->whereKey($id)->firstOrFail()->update(['disabled_at' => now()]);

                    return null;
                },
            );
        }
    }

    public function enroll(int $userId, array $data): EnrollmentResult
    {
        return $this->inner->enroll($userId, $data);
    }

    public function id(): string
    {
        return $this->inner->id();
    }

    public function kind(): FactorKind
    {
        return $this->inner->kind();
    }

    public function strength(): FactorStrength
    {
        return $this->inner->strength();
    }

    public function maxActiveCredentials(): ?int
    {
        return $this->inner->maxActiveCredentials();
    }

    public function challenge(ChallengeRequest $request): ?AuthChallenge
    {
        return $this->inner->challenge($request);
    }

    public function verify(VerificationRequest $request): FactorResult
    {
        return $this->inner->verify($request);
    }
}
