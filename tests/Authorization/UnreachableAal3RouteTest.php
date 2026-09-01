<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Authorization;

use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Tests\Support\Assurance\Aal3CapableVocabulary;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Tests\Support\Authorization\Models\PermissionedProbeUser;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\PermissionServiceProvider;

/**
 * Issue #7 — the claim the documentation makes, made executable.
 *
 * `AssuranceCeilingTest` asserts that the README says an `aal3` route is
 * unreachable under the shipped vocabulary. Nothing asserted that it IS. A
 * documentation suite can only check that prose exists; if the behaviour ever
 * changed — a vocabulary swap, a comparator that treated an underivable level
 * as satisfied — the docs would quietly become a lie and every test would stay
 * green.
 *
 * So this drives the whole path the sentence describes: configuration, route,
 * middleware, controller. The session carries the STRONGEST proof the shipped
 * vocabulary can name, which is what makes the refusal meaningful — this is not
 * a weak session being turned away, it is the best one there is.
 */
final class UnreachableAal3RouteTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Set by the controller itself, so "never reaches the controller" is a
     * claim about EXECUTION rather than about the body of the final response.
     *
     * assertDontSee() inspects only what came back. It cannot distinguish a
     * controller that never ran from one that ran, had its side effect, and
     * had its output replaced by a later middleware -- and the difference is
     * the whole point of an enforcement test.
     */
    public static bool $controllerRan = false;

    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [PermissionServiceProvider::class, VouchServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('auth.providers.users.model', PermissionedProbeUser::class);
        $app['config']->set('vouch.step_up.presentation_url', '/auth/step-up');
        $app['config']->set('vouch.assurance_requirements', ['invoices.approve' => 'aal3']);
        $app['config']->set('vouch_test.held_permissions', ['invoices.approve']);
        $app['config']->set('vouch_test.held_roles', []);
    }

    protected function setUp(): void
    {
        parent::setUp();

        self::$controllerRan = false;

        Route::middleware('web')->post('/gate/approve', function (): string {
            self::$controllerRan = true;

            return 'controller reached';
        })->middleware('can:invoices.approve');
    }

    private function signInAtTheCeiling(): void
    {
        $user = new PermissionedProbeUser();
        $user->id = 7;

        $id = $this->pinSession();

        AuthSession::create([
            'session_binding' => SessionBinding::for($id, BindingDomain::Session),
            'user_id' => 7,
            'amr' => ['password', 'totp'],
            'acr' => 'aal2',
            // Two distinct credentials: the most the shipped vocabulary names.
            'assurance_proof' => sessionProof(7, 'aal2'),
            'weakest_satisfied_at' => now(),
        ]);

        $this->actingAs($user);
    }

    #[Test]
    public function the_strongest_session_the_shipped_vocabulary_can_name_still_cannot_reach_an_aal3_route(): void
    {
        $this->signInAtTheCeiling();

        $response = $this->post('/gate/approve');

        $response->assertRedirect('/auth/step-up');
        self::assertFalse(self::$controllerRan, 'The controller ran behind an unsatisfiable requirement.');
    }

    #[Test]
    public function the_refusal_reports_a_requirement_the_holder_cannot_satisfy(): void
    {
        /*
         * The silent half of the documented claim, as far as a test can reach
         * it: the response names aal3 as required and aal2 as held, and there
         * is nothing anywhere saying that gap can never be closed. That is
         * precisely why the README has to say it.
         */
        $this->signInAtTheCeiling();

        $response = $this->withHeaders(['Accept' => 'application/json'])->post('/gate/approve');

        $response->assertStatus(403);
        $response->assertJsonPath('required', 'aal3');
        $response->assertJsonPath('held', 'aal2');
    }

    #[Test]
    public function re_proving_the_same_maximal_evidence_changes_nothing(): void
    {
        /*
         * The closest executable approach to the word "permanently", and
         * deliberately named for what it does rather than what it suggests.
         *
         * This does NOT run a step-up lifecycle, and it does NOT establish
         * anything about FRESHNESS: the rewritten proof carries the same fixed
         * factor timestamps, and this route sets no max-age, so recency could
         * not change the outcome even if it moved.
         *
         * What it establishes is narrower and still worth holding: re-writing
         * identical maximal evidence produces an identical refusal, because
         * the ceiling belongs to the vocabulary rather than to the evidence.
         * A real step-up ends in the same place for the same reason, but that
         * is an inference from this test, not something it measures.
         */
        $this->signInAtTheCeiling();

        $this->post('/gate/approve')->assertRedirect('/auth/step-up');

        AuthSession::query()->where('user_id', 7)->update([
            'assurance_proof' => sessionProof(7, 'aal2'),
            'weakest_satisfied_at' => now(),
        ]);

        $this->post('/gate/approve')->assertRedirect('/auth/step-up');
        self::assertFalse(self::$controllerRan);
    }

    #[Test]
    public function a_host_vocabulary_that_derives_aal3_does_reach_the_controller(): void
    {
        /*
         * The other half of the documented claim, and the half that makes the
         * first half honest. Everything above establishes that aal3 is
         * unreachable; on its own that reads as "Vouch cannot do aal3", which
         * is the false universal the documentation rules exist to prevent.
         *
         * The escape hatch has to be LIVE, not merely described. Same route,
         * same session, same requirement -- only the bound vocabulary differs,
         * and the request now reaches the controller. If this ever fails, the
         * README's extension point has become fiction and the ceiling really
         * is a product limit.
         */
        $this->signInAtTheCeiling();

        $this->app?->instance(AssuranceVocabulary::class, new Aal3CapableVocabulary());

        $response = $this->post('/gate/approve');

        $response->assertOk();
        self::assertTrue(self::$controllerRan, 'A vocabulary emitting aal3 did not satisfy an aal3 route.');
    }
}
