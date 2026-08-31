<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Authorization;

use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Tests\Support\Authorization\Models\PlainProbeUser;
use Fissible\Vouch\Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;

/**
 * The mirror of {@see AssuranceStrictBootTest}: strict mode must not refuse a
 * correct map, and the application it permits must still enforce.
 *
 * Asserting only that the container exists would pass against an
 * implementation that never validates anything, which is precisely the state
 * this file was written in. So it drives a real refused request instead: that
 * cannot be green unless the app booted AND the feature is wired.
 */
final class AssuranceStrictBootPassTest extends TestCase
{
    use RefreshDatabase;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('auth.providers.users.model', PlainProbeUser::class);
        $app['config']->set('vouch.step_up.presentation_url', '/auth/step-up');
        $app['config']->set('vouch.assurance_strict', true);
        $app['config']->set('vouch.declared_abilities', ['invoices.approve', 'invoices.view']);
        $app['config']->set('vouch.assurance_requirements', ['invoices.approve' => 'aal2']);
    }

    #[Test]
    public function it_boots_and_enforces_when_every_mapped_ability_is_declared(): void
    {
        Route::middleware('web')->post('/strict/approve', fn (): string => 'controller reached')
            ->middleware('can:invoices.approve');

        $id = $this->pinSession();
        AuthSession::create([
            'session_binding' => SessionBinding::for($id, BindingDomain::Session),
            'user_id' => 7,
            'amr' => ['password'],
            'acr' => 'aal1',
            'assurance_proof' => sessionProof(7, 'aal1'),
            'weakest_satisfied_at' => now(),
        ]);

        $user = new PlainProbeUser;
        $user->id = 7;

        $this->actingAs($user)->post('/strict/approve')->assertRedirect('/auth/step-up');
    }
}
