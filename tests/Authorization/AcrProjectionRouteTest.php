<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Authorization;

use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Tests\Support\Assurance\CappingVocabulary;
use Fissible\Vouch\Tests\Support\Authorization\Models\PermissionedProbeUser;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\PermissionServiceProvider;

/**
 * Issue #10 — the projection decides nothing, proven at the deployed route.
 *
 * AcrProjectionTest calls EvidenceComparator directly. That is where the rule
 * lives, but it is not where a host is exposed: an implementation could satisfy
 * the comparator and still read the column somewhere in the middleware, and the
 * unit tests would stay green while the deployed route granted on a stored
 * string.
 *
 * So these drive real requests, and the session fixtures deliberately write an
 * `acr` column that CONTRADICTS the proof stored beside it.
 */
final class AcrProjectionRouteTest extends TestCase
{
    use RefreshDatabase;

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
        $app['config']->set('vouch.assurance_requirements', ['invoices.approve' => 'aal2']);
        $app['config']->set('vouch_test.held_permissions', ['invoices.approve']);
        $app['config']->set('vouch_test.held_roles', []);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware('web')->post('/gate/approve', fn (): string => 'controller reached')
            ->middleware('can:invoices.approve');
    }

    /** Sign in with an `acr` column and a proof that need not agree. */
    private function signIn(string $storedAcr, string $proofLevel): void
    {
        $user = new PermissionedProbeUser();
        $user->id = 7;

        $id = $this->pinSession();

        AuthSession::create([
            'session_binding' => SessionBinding::for($id, BindingDomain::Session),
            'user_id' => 7,
            'amr' => ['password'],
            'acr' => $storedAcr,
            'assurance_proof' => sessionProof(7, $proofLevel),
            'weakest_satisfied_at' => now(),
        ]);

        $this->actingAs($user);
    }

    #[Test]
    public function a_stored_level_the_proof_does_not_support_never_reaches_the_controller(): void
    {
        /*
         * The row claims aal2 and the route demands aal2. Only the factors say
         * otherwise. If anything on this path trusts the column, the request
         * succeeds — which is the entire risk of storing a derived name next to
         * the evidence it came from.
         */
        $this->signIn(storedAcr: 'aal2', proofLevel: 'aal1');

        $response = $this->post('/gate/approve');

        $response->assertRedirect('/auth/step-up');
        $response->assertDontSee('controller reached');
    }

    #[Test]
    public function a_stored_level_weaker_than_the_proof_denies_nothing(): void
    {
        /*
         * The other direction, and the one that makes the pair meaningful: an
         * implementation that read the column and refused on any disagreement
         * would pass the test above and fail here.
         */
        $this->signIn(storedAcr: 'aal1', proofLevel: 'aal2');

        $this->post('/gate/approve')->assertSee('controller reached');
    }

    #[Test]
    public function the_route_refuses_under_a_stricter_vocabulary_without_rewriting_history(): void
    {
        /*
         * The migration case at the deployed route. The host binds a vocabulary
         * capping at aal1; a session that legitimately proved two credentials
         * is now short, and the row still records what it was called when it
         * was written.
         */
        $this->signIn(storedAcr: 'aal2', proofLevel: 'aal2');
        $this->app?->instance(AssuranceVocabulary::class, new CappingVocabulary());

        $this->post('/gate/approve')->assertRedirect('/auth/step-up');

        self::assertSame('aal2', AuthSession::query()->where('user_id', 7)->value('acr'));
    }

    #[Test]
    public function the_refusal_reports_the_level_the_host_vocabulary_names(): void
    {
        /*
         * The middleware's fifth call site: `held` in the 403 body. It is the
         * only place a level name reaches a client, so it must come from the
         * host's vocabulary rather than the shipped one — and it must not be
         * the stored column, which here says something else again.
         *
         * Under CappingVocabulary an aal2 proof is named aal1. A middleware
         * reading the column would report aal2; one hard-coding Nist would also
         * report aal2.
         */
        $this->signIn(storedAcr: 'aal2', proofLevel: 'aal2');
        $this->app?->instance(AssuranceVocabulary::class, new CappingVocabulary());

        /*
         * An Accept header on a normal post, NOT postJson(). Laravel's
         * postJson() prepares cookies differently and drops the pinned session
         * cookie, so the request arrives with a fresh session id, no Vouch row
         * is found, and `held` is null for a reason that has nothing to do with
         * vocabularies. The refusal still looks right, which is what makes the
         * mistake worth naming here.
         */
        $response = $this->withHeaders(['Accept' => 'application/json'])->post('/gate/approve');

        $response->assertStatus(403);
        $response->assertJsonPath('held', 'aal1');
    }
}
