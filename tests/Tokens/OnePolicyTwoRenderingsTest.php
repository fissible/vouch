<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use DateTimeImmutable;
use Fissible\Vouch\Assurance\AssuranceOutcome;
use Fissible\Vouch\Assurance\AssuranceReason;
use Fissible\Vouch\Assurance\AssuranceRequirement;
use Fissible\Vouch\Assurance\EvidenceComparator;
use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\SessionEvidence;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\ResolvedToken;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Clock\ClockInterface;

/**
 * 2.4 Task 2 — the claim the whole phase rests on, finally testable.
 *
 * "One policy, two renderings" has been an assertion in the design documents
 * since 2.4 was designed, and until now it could not be tested: there was only
 * one adapter. Task 2a built the session side; this file is where a session and
 * a token, carrying the SAME proof for the SAME subject, are put in front of the
 * SAME comparator and required to agree.
 *
 * If these ever diverge, the two surfaces have grown separate assurance models
 * and every guarantee in section 6.3 becomes a slogan. Nothing else in the suite
 * would notice: each adapter's own tests would keep passing.
 */
final class OnePolicyTwoRenderingsTest extends TestCase
{
    use DatabaseMigrations;
    use UsesSanctumSchema;

    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [SanctumServiceProvider::class, VouchServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('auth.providers.users.model', TokenUser::class);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->createTokenSubjectTables();
    }

    /** @return list<SatisfiedFactor> */
    private function proof(string $oldest = '2026-08-13T10:00:00+00:00'): array
    {
        return [
            new SatisfiedFactor('password', 'cred-1', FactorKind::Knowledge, FactorStrength::Knowledge,
                false, false, false, null, new DateTimeImmutable($oldest)),
            new SatisfiedFactor('totp', 'cred-2', FactorKind::Possession, FactorStrength::Possession,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:05:00+00:00')),
        ];
    }

    private function clock(string $now = '2026-08-13T10:10:00+00:00'): ClockInterface
    {
        return new class($now) implements ClockInterface {
            public function __construct(private string $now) {}

            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable($this->now);
            }
        };
    }

    /** Establish a real session carrying the given proof. */
    private function establishedSession(array $factors): AuthSession
    {
        TokenUser::query()->create(['id' => 7, 'name' => 'ada']);
        session()->start();

        app(SessionLifecycle::class)->establish(
            new AuthSuccess(7, $factors, AssuranceFacts::fromFactors($factors), 'ignored', 'ignored'),
        );

        return AuthSession::query()->firstOrFail();
    }

    /** Record a token assurance carrying the given proof, for the same subject. */
    private function recordedToken(array $factors, string $tokenKey = '1'): ResolvedToken
    {
        $subject = SubjectKey::of((new TokenUser)->getMorphClass(), 7);

        app(TokenAssuranceRecord::class)->store('sanctum', $tokenKey, $subject, null, ActorKind::Human, $factors);

        return new ResolvedToken('sanctum', $tokenKey, $subject, true);
    }

    #[Test]
    public function a_session_and_a_token_carrying_one_proof_produce_equal_evidence(): void
    {
        /*
         * Value equality, not "both are truthy". The factors, the subject and
         * the tenant must all survive both storage paths identically, because
         * anything the token path drops is something a policy could later read
         * on a session and not on a token.
         */
        $factors = $this->proof();
        $sessionEvidence = SessionEvidence::for($this->establishedSession($factors));
        $tokenEvidence = app(TokenAssuranceRecord::class)->read($this->recordedToken($factors))->evidence;

        self::assertNotNull($sessionEvidence);
        self::assertNotNull($tokenEvidence);
        self::assertEquals($sessionEvidence->factors, $tokenEvidence->factors);
        self::assertTrue($sessionEvidence->subject->equals($tokenEvidence->subject));
        self::assertSame($sessionEvidence->tenantId, $tokenEvidence->tenantId);
        self::assertSame($sessionEvidence->derivedAcr(), $tokenEvidence->derivedAcr());
        self::assertEquals($sessionEvidence->weakestSatisfiedAt(), $tokenEvidence->weakestSatisfiedAt());
    }

    #[Test]
    public function the_same_requirement_reaches_the_same_verdict_on_both_surfaces(): void
    {
        /*
         * The behavioural half. Equal evidence would still permit divergence if
         * each surface reached the comparator by a different route, so every
         * requirement below is judged twice and required to agree — including
         * the refusals, and including WHY they were refused.
         */
        /*
         * BOTH sides enter the comparator as an EvidenceRead. An earlier draft
         * passed the session as a bare AssuranceEvidence and the token as a
         * read result, which is asymmetric: it would keep passing under a
         * comparator that had grown a separate union arm per surface, which is
         * precisely the drift this file exists to catch.
         */
        $factors = $this->proof();
        $session = SessionEvidence::read($this->establishedSession($factors));
        $token = app(TokenAssuranceRecord::class)->read($this->recordedToken($factors));
        $comparator = app(EvidenceComparator::class);

        $requirements = [
            'met exactly' => AssuranceRequirement::from('aal2'),
            'weaker, satisfied by a stronger proof' => AssuranceRequirement::from('aal1'),
            'stronger than any derivable level' => AssuranceRequirement::from('aal3'),
            'fresh enough' => AssuranceRequirement::from(['level' => 'aal2', 'max_age' => 'PT15M']),
            'stale' => AssuranceRequirement::from(['level' => 'aal2', 'max_age' => 'PT1M']),
        ];

        foreach ($requirements as $label => $requirement) {
            $onSession = $comparator->compare($session, $requirement, $this->clock(), null);
            $onToken = $comparator->compare($token, $requirement, $this->clock(), null);

            self::assertSame($onSession->outcome, $onToken->outcome, "outcome diverged: {$label}");
            self::assertSame($onSession->reason, $onToken->reason, "reason diverged: {$label}");
        }
    }

    #[Test]
    public function recency_is_authentication_time_on_both_surfaces_not_issuance_time(): void
    {
        /*
         * The sharpest way the two could drift. A token is RECORDED later than
         * the login that justified it, so an implementation anchoring token
         * recency to issued_at would let a token outlive the freshness of the
         * very proof it was minted from — and a max_age requirement would then
         * mean two different things depending on how the caller authenticated.
         *
         * Both proofs are six weeks old. Both must be refused.
         */
        $factors = $this->proof(oldest: '2026-07-01T10:00:00+00:00');
        $session = SessionEvidence::read($this->establishedSession($factors));
        $token = app(TokenAssuranceRecord::class)->read($this->recordedToken($factors));
        $requirement = AssuranceRequirement::from(['level' => 'aal2', 'max_age' => 'PT1H']);
        $comparator = app(EvidenceComparator::class);

        self::assertSame(
            AssuranceOutcome::InsufficientRecency,
            $comparator->compare($session, $requirement, $this->clock(), null)->outcome,
        );
        self::assertSame(
            AssuranceOutcome::InsufficientRecency,
            $comparator->compare($token, $requirement, $this->clock(), null)->outcome,
        );
    }

    #[Test]
    public function both_surfaces_refuse_a_tenant_mismatch_identically(): void
    {
        $factors = $this->proof();
        $session = SessionEvidence::read($this->establishedSession($factors));
        $token = app(TokenAssuranceRecord::class)->read($this->recordedToken($factors));
        $comparator = app(EvidenceComparator::class);

        foreach ([$session, $token] as $candidate) {
            $comparison = $comparator->compare($candidate, AssuranceRequirement::from('aal1'), $this->clock(), 'acme');

            self::assertSame(AssuranceOutcome::InvalidEvidence, $comparison->outcome);
            self::assertSame(AssuranceReason::TenantMismatch, $comparison->reason);
        }
    }

    #[Test]
    public function one_read_result_type_serves_both_adapters(): void
    {
        /*
         * Structural, and it is the thing that keeps the rest of this file
         * honest. If each adapter returned its own read type, EvidenceComparator
         * would need a widening union for every surface added — and a union is
         * exactly where the second assurance model gets in. Task 2a's
         * SessionEvidenceRead is generalised rather than copied.
         */
        $factors = $this->proof();
        $sessionRead = SessionEvidence::read($this->establishedSession($factors));
        $tokenRead = app(TokenAssuranceRecord::class)->read($this->recordedToken($factors));

        self::assertInstanceOf(\Fissible\Vouch\Assurance\EvidenceRead::class, $sessionRead);
        self::assertInstanceOf(\Fissible\Vouch\Assurance\EvidenceRead::class, $tokenRead);
        self::assertSame($sessionRead::class, $tokenRead::class);

        /*
         * And the comparator's own signature carries no per-surface arm. The
         * bare AssuranceEvidence form stays — Task 2a's value-level tests judge
         * evidence with no adapter in play, which is legitimate and does not
         * create drift. What must never appear is a SECOND read type, because
         * that is a union that grows once per surface and is where the two
         * assurance models diverge.
         */
        $parameter = (new \ReflectionMethod(EvidenceComparator::class, 'compare'))->getParameters()[0];
        $arms = array_map(
            static fn (\ReflectionNamedType $t): string => $t->getName(),
            ($parameter->getType() instanceof \ReflectionUnionType) ? $parameter->getType()->getTypes() : [],
        );

        self::assertContains(\Fissible\Vouch\Assurance\EvidenceRead::class, $arms);
        self::assertNotContains(\Fissible\Vouch\Sessions\SessionEvidenceRead::class, $arms);
        self::assertCount(
            1,
            array_filter($arms, static fn (string $arm): bool => str_ends_with($arm, 'EvidenceRead')),
            'The comparator grew a second read type; that union is where the surfaces drift apart.',
        );
    }
}
