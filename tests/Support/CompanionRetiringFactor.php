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
 * A host factor whose enroll() performs more than one credential mutation.
 *
 * The enroll-side twin of CompanionRevokingFactor. `Factor::enroll()` no more
 * restricts a driver to one mutation than `revoke()` does, and retiring a
 * companion the new credential supersedes is an ordinary shape: a hardware token
 * re-registered under a new attestation, a device re-paired, a legacy row kept
 * beside the credential replacing it.
 *
 * The mutations are SEQUENTIAL -- the inner driver's finishes before the first
 * companion's begins -- which is what separates them from a mutation an observer
 * starts part way through somebody else's. Both look like "another mutation on
 * this connection" from outside, and only one of them is the caller's own work.
 *
 * It returns the inner driver's EnrollmentResult UNCHANGED, and that is not
 * laziness in the fixture -- it is the only thing a factor in this shape can do:
 *
 *   - The companion mutations' failures cannot be added to the returned result.
 *     EnrollmentResult's report is private and only the identity list is
 *     readable, so there is no report object to merge into or pass along.
 *   - Rebuilding one from the identities cannot work either. Driver revocation
 *     runs at afterCommit, which for a nested mutation is the CALLER's outermost
 *     commit -- after enroll() has returned. Every list a factor could read
 *     inside enroll() is still empty at that point, which is what
 *     'it still reports the identity once the enclosing transaction commits'
 *     already holds the shipped drivers to.
 *
 * So the report has to be a live channel the caller owns, and a driver that
 * cannot be modified -- a host's own, a third party's -- still has to be heard.
 *
 * Substituted by building a fresh FactorRegistry rather than by mutating the
 * container's singleton: registration is write-once by design and that guard is
 * not weakened to make a test observable.
 */
final class CompanionRetiringFactor implements Factor
{
    public int $enrollCalls = 0;

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

    /** @param array<string, mixed> $data */
    public function enroll(int $userId, array $data): EnrollmentResult
    {
        $this->enrollCalls++;

        $enrollment = $this->inner->enroll($userId, $data);

        foreach ($this->companions as $companion) {
            if ($companion['before'] instanceof Closure) {
                ($companion['before'])();
            }

            $this->mutated[] = $companion['id'];

            $id = $companion['id'];

            /*
             * A real mutation rather than a bare update: the point of the shape is
             * that each companion goes through the same invalidation, proof
             * withdrawal and driver-revocation path the enrolled credential's own
             * predecessor does.
             */
            app(CredentialMutation::class)->revoking(
                SubjectKey::forConfiguredUser($this->userId),
                [(string) $id],
                static function () use ($id): null {
                    /*
                     * The model instance, as every shipped driver does, not a mass
                     * update on the query builder. A builder update fires no
                     * Eloquent events, which would make these companion mutations
                     * quieter than a real factor's -- and would mean this fixture
                     * could never exercise a companion mutation that is itself
                     * observed.
                     */
                    AuthCredential::query()->whereKey($id)->firstOrFail()->update(['disabled_at' => now()]);

                    return null;
                },
            );
        }

        return $enrollment;
    }

    public function revoke(AuthCredential $credential): void
    {
        $this->inner->revoke($credential);
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
