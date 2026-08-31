<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Console;

use DateTimeImmutable;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tests\Support\Tokens\ExistenceReportingIssuer;
use Fissible\Vouch\Tests\Support\Tokens\SilentIssuer;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Tokens\TokenIssuerRegistry;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 5a — the sweep reached through `vouch:prune`, its shipped entry point.
 *
 * Folded into the existing command rather than given a second scheduled one: a
 * retention job nobody schedules is exactly how `auth_token_assurances` came to
 * ship with no policy at all.
 *
 * This does not breach that command's "never the enforcement mechanism" charter.
 * It deletes only records whose token the issuer has already confirmed absent,
 * so it cannot change the authorization outcome of any token that could still
 * authenticate — a token that no longer exists is refused by resolution, long
 * before assurance is consulted.
 */
final class PruneReclaimsTokenAssurancesTest extends TestCase
{
    use DatabaseMigrations;

    /** @return array<int, class-string> */
    protected function getPackageProviders($app): array
    {
        return [VouchServiceProvider::class];
    }

    private function record(string $issuerKey, string $tokenKey): void
    {
        app(TokenAssuranceRecord::class)->store(
            $issuerKey,
            $tokenKey,
            SubjectKey::of('App\\Models\\User', '7'),
            null,
            ActorKind::Human,
            [new SatisfiedFactor(
                'password', 'cred-1', FactorKind::Knowledge, FactorStrength::Knowledge,
                false, false, false, null, new DateTimeImmutable('2019-01-01T00:00:00+00:00'),
            )],
        );
    }

    /** @param list<object> $issuers */
    private function withIssuers(array $issuers): void
    {
        app()->instance(TokenIssuerRegistry::class, new TokenIssuerRegistry($issuers));
    }

    #[Test]
    public function prune_reclaims_records_whose_token_the_issuer_reports_absent(): void
    {
        $this->record('sanctum', 'gone');
        $this->record('sanctum', 'still-here');
        $this->withIssuers([new ExistenceReportingIssuer('sanctum', ['still-here'])]);

        self::assertSame(0, Artisan::call('vouch:prune'));

        self::assertSame(
            ['still-here'],
            DB::table('auth_token_assurances')->pluck('token_key')->all(),
        );
    }

    #[Test]
    public function prune_reports_reclaimed_retained_unsupported_and_errored_counts(): void
    {
        /*
         * A skipped issuer must be VISIBLE. The failure this guards against is
         * an operator watching a table grow with no indication that nothing is
         * able to sweep it — which is indistinguishable, from the outside, from
         * a sweep that is running and finding nothing.
         */
        $this->record('sanctum', 'gone');
        $this->record('sanctum', 'kept');
        $this->record('legacy', 'unanswerable');
        $this->record('broken', 'unreachable');

        $this->withIssuers([
            new ExistenceReportingIssuer('sanctum', ['kept']),
            new SilentIssuer('legacy'),
            new ExistenceReportingIssuer('broken', [], throws: new \RuntimeException('driver down')),
        ]);

        self::assertSame(0, Artisan::call('vouch:prune'));
        $output = strtolower(Artisan::output());

        /*
         * Each label asserted WITH its value. Checking that the output merely
         * contains the four words and the digit 1 passes with static labels,
         * transposed counts, or a number that came from somewhere else
         * entirely — which is the same defect as a test that only checks a
         * status code.
         *
         * Matched by regex rather than by exact line so the command keeps
         * control of its own layout; what is contracted is that each count is
         * reported and correct, not how it is spaced.
         */
        foreach (['reclaimed' => 1, 'retained' => 1, 'unsupported' => 1, 'errored' => 1] as $label => $expected) {
            self::assertMatchesRegularExpression(
                '/' . $label . '\D{0,20}' . $expected . '\b/',
                $output,
                sprintf('Expected %s to be reported as %d.', $label, $expected),
            );
        }
    }

    #[Test]
    public function a_failing_sweep_does_not_fail_the_whole_prune(): void
    {
        /*
         * The command's other duties — attempts, challenges, revoked sessions,
         * throttle state, delivery health — must not stop because one issuer's
         * driver is unreachable. Retention that is all-or-nothing across
         * subsystems degrades to nothing.
         */
        $this->record('broken', 'unreachable');
        $this->withIssuers([new ExistenceReportingIssuer('broken', [], throws: new \RuntimeException('driver down'))]);

        self::assertSame(0, Artisan::call('vouch:prune'));

        self::assertSame(1, DB::table('auth_token_assurances')->count());
        self::assertStringContainsString('driver down', Artisan::output());
    }

    #[Test]
    public function prune_never_reclaims_when_no_issuer_can_answer(): void
    {
        /*
         * "Nothing was deleted" is not sufficient on its own: it is also true
         * when the sweep does not exist. So this asserts the sweep RAN and
         * reported the issuer it could not ask, which is false until the
         * feature is there.
         */
        $this->record('legacy', 'unanswerable');
        $this->withIssuers([new SilentIssuer('legacy')]);

        self::assertSame(0, Artisan::call('vouch:prune'));
        $output = strtolower(Artisan::output());

        self::assertSame(1, DB::table('auth_token_assurances')->count());
        self::assertStringContainsString('unsupported', $output);
        self::assertStringContainsString('legacy', $output);
    }
}
