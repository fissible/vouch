<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Authorization;

use Fissible\Vouch\Console\CommandExit;
use Fissible\Vouch\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\Test;

/**
 * Strict mode must not lock a host out of the tool that diagnoses it.
 *
 * `vouch.assurance_strict` refuses the boot — see {@see AssuranceStrictBootTest}.
 * A host who has just been refused needs `vouch:assurance-map` to learn WHICH
 * key is wrong, and a diagnostic that inherits the failure it diagnoses is
 * useless. VouchDoctorCommand already carries this exemption; this is the
 * same shape.
 *
 * The exemption is decided from `$_SERVER['argv']`, exactly as
 * `isDoctorCommand()` decides its own, so the argv a real
 * `php artisan vouch:assurance-map` invocation produces is what is simulated
 * here. Asserting this from a normally-booted test would prove nothing: the
 * boot the exemption has to survive would already have happened.
 */
final class AssuranceStrictBootDiagnosticTest extends TestCase
{
    /** @var array<int, string> */
    private array $originalArgv = [];

    protected function setUp(): void
    {
        /** @var array<int, string> $argv */
        $argv = $_SERVER['argv'] ?? [];
        $this->originalArgv = $argv;
        $_SERVER['argv'] = ['artisan', 'vouch:assurance-map'];

        parent::setUp();
    }

    protected function tearDown(): void
    {
        $_SERVER['argv'] = $this->originalArgv;

        parent::tearDown();
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('vouch.assurance_strict', true);
        $app['config']->set('vouch.declared_abilities', ['invoices.approve']);
        $app['config']->set('vouch.assurance_requirements', ['invoices.aprove' => 'aal2']);
    }

    #[Test]
    public function it_boots_for_the_diagnostic_command_despite_the_strict_violation(): void
    {
        self::assertNotNull($this->app);
    }

    #[Test]
    public function the_diagnostic_names_the_key_that_refused_the_boot(): void
    {
        Artisan::call('vouch:assurance-map');

        self::assertStringContainsString('invoices.aprove', Artisan::output());
    }

    #[Test]
    public function the_diagnostic_reports_the_violation_as_a_failure_under_strict(): void
    {
        self::assertSame(
            CommandExit::Failure->value,
            Artisan::call('vouch:assurance-map', ['--strict' => true]),
        );
    }
}
