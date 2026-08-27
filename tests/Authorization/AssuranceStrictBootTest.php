<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Authorization;

use Fissible\Vouch\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Throwable;

/**
 * `vouch.assurance_strict` refuses the BOOT, not the request (2.3d Task 5b).
 *
 * A typo in the map is not a runtime condition — it is wrong the moment it is
 * written, and every request it should have protected is unprotected until
 * someone notices. A host that opts into strict mode is asking to be told at
 * boot rather than in an incident review.
 *
 * The failure is captured here rather than asserted with `expectException`,
 * because Testbench boots the application inside `setUp()`.
 */
final class AssuranceStrictBootTest extends TestCase
{
    private ?Throwable $bootFailure = null;

    protected function setUp(): void
    {
        try {
            parent::setUp();
        } catch (Throwable $failure) {
            $this->bootFailure = $failure;
        }
    }

    protected function tearDown(): void
    {
        if ($this->bootFailure === null) {
            parent::tearDown();

            return;
        }

        /*
         * The refused boot got as far as installing Laravel's error and
         * exception handlers, and never reached the teardown that removes
         * them. PHPUnit marks a test risky for leaking handlers, and
         * phpunit.xml.dist sets failOnRisky, so leaving them would turn this
         * proof into a CI failure for a reason unrelated to what it proves.
         */
        restore_error_handler();
        restore_exception_handler();
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('vouch.assurance_strict', true);
        $app['config']->set('vouch.declared_abilities', ['invoices.approve']);
        $app['config']->set('vouch.assurance_requirements', ['invoices.aprove' => 'aal2']);
    }

    #[Test]
    public function it_refuses_to_boot_on_an_undeclared_ability(): void
    {
        self::assertInstanceOf(RuntimeException::class, $this->bootFailure);
    }

    #[Test]
    public function it_names_the_offending_ability_in_the_refusal(): void
    {
        self::assertStringContainsString('invoices.aprove', (string) $this->bootFailure?->getMessage());
    }
}
