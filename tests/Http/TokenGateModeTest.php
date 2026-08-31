<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Http;

use DateTimeImmutable;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tests\Support\Http\AssertsTokenGateResponses;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 4 — the gate ships UNARMED.
 *
 * RejectsUnrecordedTokens installs itself into the host's `web` and `api`
 * groups, and §6.5 point 4 forbids backfilling pre-existing tokens. Armed by
 * default those two facts combine badly: installing Vouch would invalidate
 * every Sanctum token the host had ever issued, on every API route, the moment
 * the package booted. No staging, no warning, no way back except reissuing
 * every token at once.
 *
 * This package already knows the answer. From config/vouch.php, on throttle
 * dimensions with a FAR smaller blast radius: "Their blast radius makes opt-in
 * enforcement the only safe default." The token gate has the largest blast
 * radius in the package and must follow the same rule.
 *
 * Observe is therefore the default, and it is a RECORDED decision rather than a
 * silent pass — mirroring ThrottleDecision::Observed. A host installs, watches
 * which tokens would break, reissues them through Vouch::issueToken, and arms
 * the gate when the log goes quiet.
 */
final class TokenGateModeTest extends TestCase
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
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->travelTo(new DateTimeImmutable('2026-08-13T10:10:00+00:00'));
        $this->createTokenSubjectTables();
        TokenUser::query()->create(['id' => 7, 'name' => 'ada']);

        Route::middleware(['api', 'vouch.token:aal2'])->get('/gated', fn (): string => 'reached');
    }

    private function subject(int $id = 7): SubjectKey
    {
        return SubjectKey::of((new TokenUser)->getMorphClass(), $id);
    }

    /** A real Sanctum token with no Vouch assurance record — what every host already has. */
    private function preExistingToken(): string
    {
        return TokenUser::query()->findOrFail(7)->createToken('legacy')->plainTextToken;
    }

    /** A recorded token whose proof is too weak for the route. */
    private function weaklyRecordedToken(): string
    {
        $new = TokenUser::query()->findOrFail(7)->createToken('api');

        app(TokenAssuranceRecord::class)->store(
            'sanctum', stringValue($new->accessToken->getKey()), $this->subject(), null, ActorKind::Human,
            [new SatisfiedFactor('password', 'cred-1', FactorKind::Knowledge, FactorStrength::Knowledge,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'))],
        );

        return $new->plainTextToken;
    }

    #[Test]
    public function the_gate_is_unarmed_by_default(): void
    {
        /*
         * THE install-safety test. A host that installs Vouch and configures
         * nothing must keep working. Without this, `composer require` is a
         * breaking change for every API consumer the host has.
         */
        self::assertSame('observe', config('vouch.token_gate.mode'));

        $this->withToken($this->preExistingToken())->getJson('/gated')->assertOk()->assertSee('reached');
    }

    #[Test]
    public function observe_mode_records_what_it_would_have_refused(): void
    {
        /*
         * Observed, not silently permitted — the distinction
         * ThrottleDecision::Observed already draws. A mode that passed traffic
         * without saying so would give a host no way to know when it is safe to
         * arm, which is the entire purpose of the mode.
         *
         * The record names the token, so an operator can find and reissue it.
         * It must NOT name the plaintext.
         */
        $records = $this->captureLog();

        $plain = $this->preExistingToken();
        $this->withToken($plain)->getJson('/gated')->assertOk();

        $observed = array_values(array_filter(
            $records->records,
            static fn (array $r): bool => ($r['context']['reason'] ?? null) === 'no_assurance_record',
        ));

        self::assertCount(1, $observed, 'Observe mode recorded nothing an operator could act on.');
        self::assertSame('warning', $observed[0]['level']);
        self::assertSame('sanctum', $observed[0]['context']['issuer_key'] ?? null);
        self::assertNotSame('', stringValue($observed[0]['context']['token_key'] ?? ''));
        self::assertStringNotContainsString(
            $plain,
            stringValue(json_encode($observed[0])),
            'The plaintext token reached the log.',
        );
    }

    #[Test]
    public function observe_mode_records_an_insufficient_assurance_too(): void
    {
        // Not only unrecorded tokens. A host arming the gate needs to know
        // about recorded-but-too-weak tokens as well, or arming still breaks
        // callers it never saw in the log.
        $records = $this->captureLog();

        $this->withToken($this->weaklyRecordedToken())->getJson('/gated')->assertOk();

        $reasons = array_map(static fn (array $r): mixed => $r['context']['reason'] ?? null, $records->records);

        self::assertContains('insufficient_assurance', $reasons);
    }

    #[Test]
    public function observe_mode_tells_the_client_nothing(): void
    {
        /*
         * The observation is for the OPERATOR. Announcing it to the caller
         * would disclose that a token is on borrowed time — the same oracle §5
         * flattens — and would leak it to anyone holding a token rather than
         * anyone reading the logs.
         */
        $response = $this->withToken($this->preExistingToken())->getJson('/gated');

        $response->assertOk();
        self::assertSame([], $response->headers->all('WWW-Authenticate'));
        self::assertNull($response->headers->get('Vouch-Token-Gate'));
    }

    #[Test]
    public function enforce_mode_refuses_exactly_as_contracted(): void
    {
        // The armed behaviour is the one every other Task 4 test pins; this
        // only proves the switch reaches it.
        config(['vouch.token_gate.mode' => 'enforce']);

        self::assertSame($this->canonicalRejection(), $this->responseTuple(
            $this->withToken($this->preExistingToken())->getJson('/gated'),
        ));
    }

    #[Test]
    public function a_recorded_token_passes_in_either_mode(): void
    {
        // Observe must not become "never enforce anything": a sufficient token
        // is admitted for the right reason, not because the mode is off.
        $new = TokenUser::query()->findOrFail(7)->createToken('api');
        app(TokenAssuranceRecord::class)->store(
            'sanctum', stringValue($new->accessToken->getKey()), $this->subject(), null, ActorKind::Human,
            [
                new SatisfiedFactor('password', 'cred-1', FactorKind::Knowledge, FactorStrength::Knowledge,
                    false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00')),
                new SatisfiedFactor('totp', 'cred-2', FactorKind::Possession, FactorStrength::Possession,
                    false, false, false, null, new DateTimeImmutable('2026-08-13T10:05:00+00:00')),
            ],
        );

        foreach (['observe', 'enforce'] as $mode) {
            config(['vouch.token_gate.mode' => $mode]);

            $this->withToken($new->plainTextToken)->getJson('/gated')->assertOk()->assertSee('reached');
        }
    }

    #[Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('invalidModes')]
    public function an_unrecognised_mode_is_a_loud_configuration_error(mixed $mode): void
    {
        /*
         * Exactly "observe" or "enforce", matching ThrottleConfiguration's rule
         * and its loud failure. A typo must not silently disarm the gate — an
         * unrecognised value defaulting to observe is how a host believes it is
         * protected and is not.
         */
        config(['vouch.token_gate.mode' => $mode]);

        $this->expectException(\InvalidArgumentException::class);

        $this->withoutExceptionHandling()
            ->withToken($this->preExistingToken())
            ->getJson('/gated');
    }

    /** @return array<string, array{mixed}> */
    public static function invalidModes(): array
    {
        return [
            'typo' => ['enforced'],
            'boolean' => [true],
            'empty' => [''],
            'null' => [null],
        ];
    }

    /**
     * Capture log records through Laravel's own listener rather than a facade
     * mock, so the assertion is about what was logged rather than about how the
     * facade was called.
     *
     * @return object{records: list<array{level: string, message: string, context: array<string, mixed>}>}
     */
    private function captureLog(): object
    {
        $sink = new class {
            /** @var list<array{level: string, message: string, context: array<string, mixed>}> */
            public array $records = [];
        };

        Log::listen(function (MessageLogged $message) use ($sink): void {
            $sink->records[] = [
                'level' => $message->level,
                'message' => $message->message,
                'context' => $message->context,
            ];
        });

        return $sink;
    }
}