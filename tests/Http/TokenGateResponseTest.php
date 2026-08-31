<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Http;

use DateTimeImmutable;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Http\AssertsTokenGateResponses;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 4 — the RFC 9470 wire contract, asserted byte for byte.
 *
 * This is a protocol, not a message. A client parses `WWW-Authenticate`
 * mechanically to decide whether to re-authenticate more strongly, so a stray
 * space, an unquoted parameter or a folded line is a bug for every consumer at
 * once — and none of it shows up in a test that only checks the status code.
 *
 * Addendum §5 fixes the exact bytes. The four indistinguishable cases must be
 * BYTE-IDENTICAL: telling a caller which of them applied is the disclosure the
 * flattening exists to prevent.
 */
final class TokenGateResponseTest extends TestCase
{
    use AssertsTokenGateResponses;
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
        $app['config']->set('vouch.assurance_requirements', []);
    }

    protected function setUp(): void
    {
        parent::setUp();

        /*
         * A FIXED CLOCK, because the routes below demand PT15M recency. An
         * earlier draft minted proofs dated 2026-08-13 and asserted they passed
         * a fifteen-minute requirement at the real clock — every success test
         * would have failed on recency rather than proving anything about the
         * gate.
         */
        $this->travelTo(new DateTimeImmutable('2026-08-13T10:10:00+00:00'));

        $this->createTokenSubjectTables();
        TokenUser::query()->create(['id' => 7, 'name' => 'ada']);

        Route::middleware(['api', 'vouch.token:aal2,PT15M'])->get('/gated', fn (): string => 'reached');
        Route::middleware(['api', 'vouch.token'])->get('/gated-any', fn (): string => 'reached');
    }

    private function subject(int $id = 7): SubjectKey
    {
        return SubjectKey::of((new TokenUser)->getMorphClass(), $id);
    }

    /** @return list<SatisfiedFactor> */
    private function proof(string $oldest = '2026-08-13T10:00:00+00:00', bool $strong = true): array
    {
        $factors = [
            new SatisfiedFactor('password', 'cred-1', FactorKind::Knowledge, FactorStrength::Knowledge,
                false, false, false, null, new DateTimeImmutable($oldest)),
        ];

        if ($strong) {
            $factors[] = new SatisfiedFactor('totp', 'cred-2', FactorKind::Possession, FactorStrength::Possession,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:05:00+00:00'));
        }

        return $factors;
    }

    /**
     * Mint a real Sanctum token and record assurance for it.
     *
     * @param  list<SatisfiedFactor>|null  $factors
     */
    private function recordedToken(?array $factors = null, ActorKind $actor = ActorKind::Human): string
    {
        $user = TokenUser::query()->findOrFail(7);
        $new = $user->createToken('api');

        app(TokenAssuranceRecord::class)->store(
            'sanctum',
            stringValue($new->accessToken->getKey()),
            $this->subject(),
            null,
            $actor,
            $factors ?? $this->proof(),
        );

        return $new->plainTextToken;
    }


    #[Test]
    public function a_recorded_token_meeting_the_requirement_passes_through(): void
    {
        $this->withToken($this->recordedToken())->getJson('/gated')->assertOk()->assertSee('reached');
    }

    #[Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('indistinguishableCases')]
    public function the_indistinguishable_cases_are_byte_identical(string $case): void
    {
        /*
         * Every rejection Vouch itself produces renders the same bytes.
         * Separating them would tell a caller whether a subject exists, whether
         * a record exists, or what actor class it holds — the oracle §5 flattens.
         *
         * NOTE what is NOT here. An earlier draft included invalid, expired and
         * revoked tokens. Sanctum returns no principal for those, so no issuer
         * claims the request, §2 requires it to pass through, and producing
         * invalid_token would take the header sniffing §2 forbids. They are the
         * host auth layer's to answer: Vouch gates assurance, not
         * authentication. §5 is amended to match.
         */
        $token = $this->prepareCase($case);

        $response = $this->withToken($token)->getJson('/gated');

        self::assertSame($this->canonicalRejection(), $this->responseTuple($response), "case: {$case}");
    }

    /** @return array<string, array{string}> */
    public static function indistinguishableCases(): array
    {
        return [
            'recorded by nobody' => ['unrecorded'],
            'record names another subject' => ['subject-mismatch'],
            'machine actor on a human route' => ['machine'],
            'stored proof malformed' => ['malformed'],
        ];
    }



    private function prepareCase(string $case): string
    {
        $user = TokenUser::query()->findOrFail(7);

        return match ($case) {
            // Minted straight through Sanctum, bypassing Vouch::issueToken —
            // the case the whole gate exists for.
            'unrecorded' => $user->createToken('api')->plainTextToken,
            'subject-mismatch' => (function () use ($user): string {
                $new = $user->createToken('api');
                app(TokenAssuranceRecord::class)->store('sanctum', stringValue($new->accessToken->getKey()),
                    SubjectKey::of((new TokenUser)->getMorphClass(), 8), null, ActorKind::Human, $this->proof());

                return $new->plainTextToken;
            })(),
            'machine' => $this->machineTokenWithHumanProof(),
            'malformed' => (function () use ($user): string {
                $new = $user->createToken('api');
                app(TokenAssuranceRecord::class)->store('sanctum', stringValue($new->accessToken->getKey()),
                    $this->subject(), null, ActorKind::Human, $this->proof());
                DB::table('auth_token_assurances')->update(['assurance_proof' => '"not an envelope"']);

                return $new->plainTextToken;
            })(),
            default => throw new \InvalidArgumentException("Unknown case {$case}."),
        };
    }

    /**
     * A machine record that ALSO carries otherwise-sufficient human proof.
     *
     * The discriminator for actor ordering. A record with no factors renders
     * invalid_token whether actor policy is selected first or human evidence is
     * read and then flattened — so it proves nothing about the order. This row
     * would satisfy the route on its human evidence alone, so an implementation
     * that reads evidence before selecting actor class returns 200 or a
     * challenge, and fails.
     *
     * Written directly, because TokenAssuranceRecord refuses to STORE this
     * combination — which is correct, and is why the inconsistent row has to be
     * forged to test the reader.
     */
    private function machineTokenWithHumanProof(): string
    {
        $user = TokenUser::query()->findOrFail(7);
        $new = $user->createToken('api');

        app(TokenAssuranceRecord::class)->store('sanctum', stringValue($new->accessToken->getKey()),
            $this->subject(), null, ActorKind::Human, $this->proof());

        DB::table('auth_token_assurances')->update(['actor_kind' => 'machine']);

        return $new->plainTextToken;
    }

    #[Test]
    public function an_insufficient_level_renders_a_step_up_challenge(): void
    {
        /*
         * The distinction §5 keeps: this token IS recorded and IS the bearer's,
         * so re-authenticating more strongly would actually help. Collapsing it
         * into invalid_token forfeits the affordance RFC 9470 exists for.
         */
        $token = $this->recordedToken($this->proof(strong: false));

        $response = $this->withToken($token)->getJson('/gated');

        self::assertSame($this->canonicalChallenge('aal2', 900), $this->responseTuple($response));
    }

    #[Test]
    public function an_insufficient_recency_renders_the_same_challenge_shape(): void
    {
        // Level is met; the proof is six weeks old against a PT15M requirement.
        $token = $this->recordedToken($this->proof(oldest: '2026-07-01T10:00:00+00:00'));

        $this->travelTo(new DateTimeImmutable('2026-08-13T12:00:00+00:00'));

        $response = $this->withToken($token)->getJson('/gated');

        self::assertSame($this->canonicalChallenge('aal2', 900), $this->responseTuple($response));
    }

    #[Test]
    public function the_challenge_is_one_physical_line_with_quoted_parameters(): void
    {
        /*
         * RFC 7230 §3.2.4 retired obsolete line folding, and §5 says any wrapped
         * rendering in the specs is illustrative. A folded header is rejected or
         * mangled by modern clients and proxies, so this asserts the bytes
         * directly rather than trusting the framework not to wrap them.
         */
        $response = $this->withToken($this->recordedToken($this->proof(strong: false)))->getJson('/gated');
        $header = (string) $response->headers->get('WWW-Authenticate');

        // Literal equality, not a shape match. An earlier draft used [^"]+,
        // which accepts tabs and other client-visible control characters inside
        // a quoted value, and read a normalized header rather than asserting how
        // many fields were emitted.
        // The whole tuple as well, so no test in this file asserts a rejection
        // by a weaker form than the contract it claims to pin.
        self::assertSame($this->canonicalChallenge('aal2', 900), $this->responseTuple($response));
        self::assertSame(0, preg_match('/[\x00-\x1F\x7F]/', $header), 'Control characters in the challenge.');
    }

    #[Test]
    public function the_max_age_is_integer_seconds_not_an_iso_duration(): void
    {
        // Config takes ISO-8601 because it maps to DateInterval; the wire takes
        // seconds because RFC 9470 §3 says so. The conversion happens once, at
        // this boundary, and nowhere else.
        $response = $this->withToken($this->recordedToken($this->proof(strong: false)))->getJson('/gated');

        self::assertStringContainsString('max_age="900"', (string) $response->headers->get('WWW-Authenticate'));
        self::assertStringNotContainsString('PT15M', (string) $response->headers->get('WWW-Authenticate'));
    }

    #[Test]
    public function a_route_with_no_recency_requirement_omits_max_age(): void
    {
        /*
         * A level-only requirement must not acquire a default max_age. Emitting
         * one would tell a client to re-authenticate on a schedule the host
         * never configured.
         */
        config(['vouch.assurance_requirements' => []]);
        Route::middleware(['api', 'vouch.token:aal2'])->get('/gated-level-only', fn (): string => 'reached');

        /*
         * The CANONICAL TUPLE with max_age omitted, not string containment.
         * Containment left status, header multiplicity, cache control, Vary and
         * the empty body unconstrained — the third time in this contract that a
         * rejection was asserted by a weaker form than the one it claims to
         * pin. The first two were bare assertStatus(401); sweeping for that
         * shape alone missed this one, which is why canonicalChallenge() takes
         * a nullable max_age: the omission is part of the contract, not an
         * absence to check for separately.
         */
        $response = $this->withToken($this->recordedToken($this->proof(strong: false)))->getJson('/gated-level-only');

        self::assertSame($this->canonicalChallenge('aal2'), $this->responseTuple($response));
    }


    #[Test]
    public function an_issuer_reporting_the_token_unusable_renders_the_same_bytes(): void
    {
        /*
         * The fifth invalid_token case, and the only one Sanctum cannot produce.
         * §3b records why: Sanctum returns no principal for an expired or
         * revoked token, so `usable: false` never reaches the adapter through
         * it. A third-party driver whose lifecycle model CAN report
         * unusability — Passport, or a host driver over a table that marks
         * rather than deletes — does reach it, and must render identically.
         */
        $issuer = new class($this->subject()) implements \Fissible\Vouch\Contracts\TokenIssuer {
            public function __construct(private SubjectKey $subject) {}

            public function issuerKey(): string
            {
                return 'third-party';
            }

            public function supportsTransactionalIssuance(): bool
            {
                return true;
            }

            public function issue(\Illuminate\Database\ConnectionInterface $connection, \Fissible\Vouch\Tokens\TokenGrant $grant): \Fissible\Vouch\Tokens\IssuedToken
            {
                throw new \RuntimeException('not used');
            }

            public function resolveForRequest(\Illuminate\Http\Request $request): \Fissible\Vouch\Tokens\ResolvedToken
            {
                return new \Fissible\Vouch\Tokens\ResolvedToken('third-party', '1', $this->subject, usable: false);
            }

            public function revoke(string $tokenKey): void {}
        };

        app()->instance(\Fissible\Vouch\Tokens\TokenIssuerRegistry::class,
            new \Fissible\Vouch\Tokens\TokenIssuerRegistry([$issuer]));

        $response = $this->withToken('a-third-party-token')->getJson('/gated');

        self::assertSame($this->canonicalRejection(), $this->responseTuple($response));
    }

    #[Test]
    public function a_tenant_mismatch_renders_the_same_bytes(): void
    {
        /*
         * Moved here from the enforcement tests, where it asserted only a 401.
         * A rejection whose wire shape is unspecified could ship as a challenge,
         * with a body, or without cache controls — and a cross-tenant record is
         * emphatically not a step-up candidate: the credential may be aal3 and
         * still never apply here.
         */
        config(['vouch.tenant' => 'acme']);

        $user = TokenUser::query()->findOrFail(7);
        $new = $user->createToken('api');
        app(TokenAssuranceRecord::class)->store('sanctum', stringValue($new->accessToken->getKey()),
            $this->subject(), 'other-tenant', ActorKind::Human, $this->proof());

        $response = $this->withToken($new->plainTextToken)->getJson('/gated');

        self::assertSame($this->canonicalRejection(), $this->responseTuple($response));
    }
}
