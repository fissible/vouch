<?php

declare(strict_types=1);

use Fissible\Vouch\Authorization\AssuranceGateHook;
use Fissible\Vouch\Http\AssuranceComparator;
use Fissible\Vouch\Http\Middleware\RequireAbilityAssurance;
use Fissible\Vouch\Http\Middleware\RequireAssurance;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\SelfService\CredentialSelfService;
use Fissible\Vouch\SelfService\SelfServiceOutcome;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class);

/*
 * 2.4 Task 2a — the enforcement paths actually move.
 *
 * Everything else in this task could be built, be correct, and change nothing:
 * a new evidence model can sit beside the old cached-acr comparator while all
 * four production call sites -- RequireAssurance, RequireAbilityAssurance,
 * AssuranceGateHook and CredentialSelfService -- keep reading AuthSession::$acr.
 * That outcome satisfies every other file here and leaves the addendum's claim
 * exactly as false as it was before.
 *
 * These are the tests that make the migration observable rather than merely
 * available.
 */

beforeEach(function (): void {
    config(['vouch.step_up.presentation_url' => '/auth/step-up']);
});

function enforcedRequest(string $uri = '/admin/settings'): Request
{
    /*
     * The container session, not a detached Store: establishSession() rotates
     * and binds THAT session, so a separate store would never match the binding
     * and every test below would pass by finding no row at all.
     *
     * driver(), not session() itself: the helper returns a SessionManager,
     * while setLaravelSession() requires Illuminate\Contracts\Session\Session.
     * The driver is the same Store the manager proxies to, so the id — and
     * therefore the binding — is identical.
     */
    $request = Request::create($uri);
    $request->setLaravelSession(sessionStore());

    return $request;
}

function reachedHandler(): Closure
{
    return static fn (Request $request): Response => new Response('reached');
}

/** A row in the 0.1.1 shape: a level, and no proof of anything. */
function legacySessionRow(string $acr = 'aal2', int $userId = 7): AuthSession
{
    session()->start();

    return AuthSession::query()->create([
        'session_binding' => SessionBinding::for(session()->getId(), BindingDomain::Session),
        'user_id' => $userId,
        'amr' => ['password', 'totp'],
        'acr' => $acr,
        'assurance_proof' => null,
    ]);
}

it('removes the cached-level comparison rather than leaving it callable', function (): void {
    /*
     * Structural, and deliberately so: it is the only assertion that cannot be
     * satisfied by adding a new path beside the old one. The level vocabulary --
     * ORDER, isKnown(), strength() -- stays where 2.3d's AssuranceRequirements
     * already depends on it; only the comparison that reads a stored acr goes.
     */
    expect((new ReflectionClass(AssuranceComparator::class))->hasMethod('isSufficient'))->toBeFalse()
        ->and(AssuranceComparator::isKnown('aal2'))->toBeTrue();
});

it('lets a session through on the strength of its proof', function (): void {
    establishSession(proofSuccess([
        proofFactor('password', '2026-08-13T10:00:00+00:00'),
        proofFactor('totp', '2026-08-13T10:05:00+00:00', FactorStrength::Possession, 'cred-2'),
    ]));

    expect(app(RequireAssurance::class)->handle(enforcedRequest(), reachedHandler(), 'aal2')->getContent())
        ->toBe('reached');
});

it('still lets a stronger session satisfy a weaker requirement', function (): void {
    // Ordered comparison survives the migration. Refusing a stronger session is
    // a lockout that reads as a security win.
    establishSession(proofSuccess([
        proofFactor('password', '2026-08-13T10:00:00+00:00'),
        proofFactor('totp', '2026-08-13T10:05:00+00:00', FactorStrength::Possession, 'cred-2'),
    ]));

    expect(app(RequireAssurance::class)->handle(enforcedRequest(), reachedHandler(), 'aal1')->getContent())
        ->toBe('reached');
});

it('refuses a legacy session that claims a level it cannot prove', function (): void {
    /*
     * The operational cost of this task, asserted rather than described. This
     * row passes today: acr says aal2 and the comparator believes it. After 2a
     * it proves nothing, and its holder re-authenticates.
     */
    legacySessionRow('aal2');

    $response = app(RequireAssurance::class)->handle(enforcedRequest(), reachedHandler(), 'aal2');

    expect($response->getContent())->not->toBe('reached')
        ->and($response->headers->get('Location'))->toBe('/auth/step-up');
});

it('refuses a session whose stored level was tampered upward', function (): void {
    /*
     * The proof is a single knowledge factor; the acr column is edited to claim
     * aal3. An implementation that kept reading the column passes this and
     * fails nothing else in the suite.
     */
    $session = establishSession(proofSuccess());
    DB::table('auth_sessions')->where('id', $session->id)->update(['acr' => 'aal3']);

    $response = app(RequireAssurance::class)->handle(enforcedRequest(), reachedHandler(), 'aal3');

    expect($response->getContent())->not->toBe('reached');
});

it('refuses an interactive route whose requirement has gone stale', function (): void {
    /*
     * Recency reaches the interactive path here for the first time. 0.1.1 could
     * not express it at all -- there was no timestamp authorization read -- so
     * this is new behaviour, not a regression guard.
     */
    Illuminate\Support\Carbon::setTestNow(Illuminate\Support\Carbon::parse('2026-08-13T12:00:00+00:00'));
    establishSession(proofSuccess([proofFactor('password', '2026-08-13T10:00:00+00:00')]));

    $response = app(RequireAssurance::class)->handle(
        enforcedRequest(),
        reachedHandler(),
        'aal1',
        'PT15M',
    );

    expect($response->getContent())->not->toBe('reached');
});

it('keeps the single-argument route form working', function (): void {
    /*
     * DECISION MADE HERE, not inherited from the addendum, which specifies the
     * config and wire forms but not the route form. A second optional middleware
     * argument -- `assurance:aal2,PT15M` -- is the idiomatic Laravel shape and
     * leaves every `assurance:aal2` route published in 0.1.1 parsing unchanged.
     * The rejected alternative was encoding a structure into the single
     * argument, which makes the common case unreadable to express the rare one.
     */
    establishSession(proofSuccess([proofFactor('password', '2026-08-13T10:00:00+00:00')]));

    expect(app(RequireAssurance::class)->handle(enforcedRequest(), reachedHandler(), 'aal1')->getContent())
        ->toBe('reached');
});

it('refuses a route whose recency argument is malformed', function (): void {
    // A max_age that failed to parse must not degrade to "no recency limit",
    // which would silently unenforce the stricter of the two halves.
    establishSession(proofSuccess());

    expect(fn () => app(RequireAssurance::class)->handle(enforcedRequest(), reachedHandler(), 'aal1', '15 minutes'))
        ->toThrow(InvalidArgumentException::class);
});

it('refuses credential self-service to a legacy session', function (): void {
    /*
     * The sharpest consequence, and the reason this task gates the rest of 2.4.
     * changePassword() requires aal2. A pre-2a row carrying acr='aal2' and no
     * proof can mutate credentials today; after this it cannot.
     */
    $session = legacySessionRow('aal2');

    expect(app(CredentialSelfService::class)->changePassword($session, 'a-new-password'))
        ->toBe(SelfServiceOutcome::StepUpRequired);
});

it('allows credential self-service on a proven session', function (): void {
    // The other half: the refusal above must come from the missing proof, not
    // from self-service having been broken wholesale.
    $session = establishSession(proofSuccess([
        proofFactor('password', '2026-08-13T10:00:00+00:00'),
        proofFactor('totp', '2026-08-13T10:05:00+00:00', FactorStrength::Possession, 'cred-2'),
    ]));

    expect(app(CredentialSelfService::class)->changePassword($session, 'a-new-password'))
        ->not->toBe(SelfServiceOutcome::StepUpRequired);
});

it('denies a mapped ability to a legacy session at the gate hook', function (): void {
    config(['vouch.assurance_requirements' => ['settings.manage' => 'aal2']]);
    legacySessionRow('aal2');

    $user = new class {
        public function getAuthIdentifier(): int
        {
            return 7;
        }
    };

    expect(app(AssuranceGateHook::class)->decide($user, 'settings.manage', enforcedRequest()))
        ->toBeFalse();
});

it('leaves an unmapped ability alone, even for a legacy session', function (): void {
    // The hook is deny-only. Turning "no proof" into a denial for abilities
    // Vouch was never asked about would break every host authorization rule.
    config(['vouch.assurance_requirements' => ['settings.manage' => 'aal2']]);
    legacySessionRow('aal2');

    $user = new class {
        public function getAuthIdentifier(): int
        {
            return 7;
        }
    };

    expect(app(AssuranceGateHook::class)->decide($user, 'posts.view', enforcedRequest()))
        ->toBeNull();
});

/*
 * RequireAbilityAssurance.
 *
 * Its fixtures were realigned to carry proofs, which means they no longer
 * discriminate: an implementation that swapped isSufficient() for a private
 * helper still reading AuthSession::$acr passes all of them, because every
 * fixture's acr now agrees with its proof. These are the two rows where the two
 * disagree, and they are the only tests on this path that can tell the
 * implementations apart.
 */

function abilityRequest(string $uri = '/invoices/approve'): Request
{
    $request = Request::create($uri);
    $request->setLaravelSession(sessionStore());
    $request->setRouteResolver(static function () use ($uri): Illuminate\Routing\Route {
        $route = new Illuminate\Routing\Route(['GET'], $uri, ['middleware' => ['can:invoices.approve']]);

        return $route->bind(Request::create($uri));
    });

    return $request;
}

function abilityUser(int $id = 7): object
{
    return new class($id) {
        public function __construct(private int $id) {}

        public function getAuthIdentifier(): int
        {
            return $this->id;
        }
    };
}

it('refuses a mapped ability to a legacy proofless session', function (): void {
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal2']]);
    legacySessionRow('aal2');

    $request = abilityRequest();
    $request->setUserResolver(static fn (): object => abilityUser());

    $response = app(RequireAbilityAssurance::class)->handle($request, reachedHandler());

    expect($response->getContent())->not->toBe('reached')
        ->and($response->getStatusCode())->not->toBe(200);
});

it('refuses a mapped ability when the stored level was tampered upward', function (): void {
    /*
     * The proof is a single knowledge factor, deriving aal1; acr is edited to
     * claim aal2, which is what the route requires. Reading the column admits
     * the request. Re-deriving from the proof refuses it.
     */
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal2']]);
    $session = establishSession(proofSuccess());
    DB::table('auth_sessions')->where('id', $session->id)->update(['acr' => 'aal2']);

    $request = abilityRequest();
    $request->setUserResolver(static fn (): object => abilityUser());

    $response = app(RequireAbilityAssurance::class)->handle($request, reachedHandler());

    expect($response->getContent())->not->toBe('reached');
});

it('admits a mapped ability on a session that genuinely proves the level', function (): void {
    // The counterpart, so the two refusals above cannot pass by the middleware
    // having been broken outright.
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal2']]);
    establishSession(proofSuccess([
        proofFactor('password', '2026-08-13T10:00:00+00:00'),
        proofFactor('totp', '2026-08-13T10:05:00+00:00', FactorStrength::Possession, 'cred-2'),
    ]));

    $request = abilityRequest();
    $request->setUserResolver(static fn (): object => abilityUser());

    expect(app(RequireAbilityAssurance::class)->handle($request, reachedHandler())->getContent())
        ->toBe('reached');
});

it('never reports a derived level it did not authorize from', function (): void {
    /*
     * The JSON refusal body carries `held`, which today is AuthSession::$acr --
     * a value authorization no longer reads. Reporting the stored string while
     * refusing on the derived one would hand an operator a body that contradicts
     * the decision it explains.
     */
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal2']]);
    $session = establishSession(proofSuccess());
    DB::table('auth_sessions')->where('id', $session->id)->update(['acr' => 'aal2']);

    $request = abilityRequest();
    $request->headers->set('Accept', 'application/json');
    $request->setUserResolver(static fn (): object => abilityUser());

    $response = app(RequireAbilityAssurance::class)->handle($request, reachedHandler());
    $body = jsonBody($response->getContent());

    expect($response->getStatusCode())->toBe(403)
        ->and($body['held'])->toBe('aal1');
});

it('reports no held level when there is no usable evidence', function (array $extra): void {
    /*
     * The JSON body's `held` field must never name a level authorization did
     * not read. The tampered-upward case covers a row whose evidence derives
     * SOMETHING; these are the rows where it derives nothing at all, and where
     * echoing the stored acr would tell a client the session holds aal2 in the
     * same response that refuses it for aal2.
     */
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal2']]);
    session()->start();

    AuthSession::query()->create(array_merge([
        'session_binding' => SessionBinding::for(session()->getId(), BindingDomain::Session),
        'user_id' => 7,
        'amr' => ['password', 'totp'],
        'acr' => 'aal2',
    ], $extra));

    $request = abilityRequest();
    $request->headers->set('Accept', 'application/json');
    $request->setUserResolver(static fn (): object => abilityUser());

    $response = app(RequireAbilityAssurance::class)->handle($request, reachedHandler());
    $body = jsonBody($response->getContent());

    expect($response->getStatusCode())->toBe(403)
        ->and($body['held'])->toBeNull();
})->with([
    'legacy row with no proof' => [['assurance_proof' => null]],
    'corrupt proof' => [['assurance_proof' => ['subject' => 'App\\Models\\User:7', 'factors' => [['factor_id' => 'password']]]]],
]);
