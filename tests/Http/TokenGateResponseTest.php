<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Http;

use DateTimeImmutable;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
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

    /** The exact single line an RFC 9470 challenge must be. */
    private function challengeLine(string $level, int $maxAge): string
    {
        return 'Bearer error="insufficient_user_authentication", '
            . 'error_description="A higher assurance level is required", '
            . 'acr_values="vouch:' . $level . '", max_age="' . $maxAge . '"';
    }

    #[Test]
    public function a_recorded_token_meeting_the_requirement_passes_through(): void
    {
        $this->withToken($this->recordedToken())->getJson('/gated')->assertOk()->assertSee('reached');
    }

    #[Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('indistinguishableCases')]
    public function the_four_indistinguishable_cases_are_byte_identical(string $case): void
    {
        /*
         * Invalid, expired, revoked and unrecorded all render the same bytes.
         * Anything that separated them would tell a caller holding a bad token
         * WHICH kind of bad it was — that a token exists but is expired, or that
         * a subject is real but not the bearer — which is exactly the oracle
         * §5 flattens.
         */
        $token = $this->prepareCase($case);

        $response = $this->withToken($token)->getJson('/gated');

        $response->assertStatus(401);
        self::assertSame('Bearer error="invalid_token"', $response->headers->get('WWW-Authenticate'));
        self::assertSame('', $response->getContent(), 'No detail may travel in the body.');
        self::assertSame('no-store', $response->headers->get('Cache-Control'));
        self::assertSame('Authorization, Cookie', $response->headers->get('Vary'));
    }

    /** @return array<string, array{string}> */
    public static function indistinguishableCases(): array
    {
        return [
            'unparseable token' => ['invalid'],
            'expired token' => ['expired'],
            'revoked token' => ['revoked'],
            'recorded by nobody' => ['unrecorded'],
        ];
    }

    private function prepareCase(string $case): string
    {
        $user = TokenUser::query()->findOrFail(7);

        return match ($case) {
            'invalid' => 'not-a-real-token',
            'expired' => (function () use ($user): string {
                $new = $user->createToken('api');
                app(TokenAssuranceRecord::class)->store('sanctum', stringValue($new->accessToken->getKey()),
                    $this->subject(), null, ActorKind::Human, $this->proof());
                $new->accessToken->forceFill(['expires_at' => now()->subDay()])->save();

                return $new->plainTextToken;
            })(),
            'revoked' => (function () use ($user): string {
                $new = $user->createToken('api');
                app(TokenAssuranceRecord::class)->store('sanctum', stringValue($new->accessToken->getKey()),
                    $this->subject(), null, ActorKind::Human, $this->proof());
                $new->accessToken->delete();

                return $new->plainTextToken;
            })(),
            // Minted directly through Sanctum, bypassing Vouch::issueToken —
            // the case the whole gate exists for.
            'unrecorded' => $user->createToken('api')->plainTextToken,
            default => throw new \InvalidArgumentException("Unknown case {$case}."),
        };
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

        $response->assertStatus(401);
        self::assertSame($this->challengeLine('aal2', 900), $response->headers->get('WWW-Authenticate'));
        self::assertSame('', $response->getContent());
    }

    #[Test]
    public function an_insufficient_recency_renders_the_same_challenge_shape(): void
    {
        // Level is met; the proof is six weeks old against a PT15M requirement.
        $token = $this->recordedToken($this->proof(oldest: '2026-07-01T10:00:00+00:00'));

        $this->travelTo(new DateTimeImmutable('2026-08-13T12:00:00+00:00'));

        $response = $this->withToken($token)->getJson('/gated');

        $response->assertStatus(401);
        self::assertSame($this->challengeLine('aal2', 900), $response->headers->get('WWW-Authenticate'));
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

        self::assertStringNotContainsString("\n", $header);
        self::assertStringNotContainsString("\r", $header);
        self::assertStringNotContainsString(",\t", $header);
        // Ordinary single spaces after commas, not folded continuations.
        self::assertSame(1, preg_match('/^Bearer error="[^"]+", error_description="[^"]+", acr_values="[^"]+", max_age="\d+"$/', $header));
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

        $response = $this->withToken($this->recordedToken($this->proof(strong: false)))->getJson('/gated-level-only');

        $header = (string) $response->headers->get('WWW-Authenticate');

        self::assertStringContainsString('acr_values="vouch:aal2"', $header);
        self::assertStringNotContainsString('max_age', $header);
    }

    #[Test]
    public function a_machine_token_is_refused_as_invalid_not_challenged(): void
    {
        /*
         * Actor class is selected BEFORE the human-evidence reader, which
         * correctly reports a machine record as unusable human evidence. A
         * challenge here would invite a service to present a factor it does not
         * have and cannot acquire.
         */
        $token = $this->recordedToken([], ActorKind::Machine);

        $response = $this->withToken($token)->getJson('/gated');

        $response->assertStatus(401);
        self::assertSame('Bearer error="invalid_token"', $response->headers->get('WWW-Authenticate'));
    }

    #[Test]
    public function a_subject_mismatch_is_invalid_rather_than_insufficient(): void
    {
        // The record names someone else. That is not a weak credential, so a
        // step-up challenge would invite strengthening one that will never apply.
        $user = TokenUser::query()->findOrFail(7);
        $new = $user->createToken('api');
        app(TokenAssuranceRecord::class)->store('sanctum', stringValue($new->accessToken->getKey()),
            SubjectKey::of((new TokenUser)->getMorphClass(), 8), null, ActorKind::Human, $this->proof());

        $response = $this->withToken($new->plainTextToken)->getJson('/gated');

        $response->assertStatus(401);
        self::assertSame('Bearer error="invalid_token"', $response->headers->get('WWW-Authenticate'));
    }
}
