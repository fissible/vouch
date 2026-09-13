<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Http\Middleware\ValidatesVouchSession;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class);

/*
 * Issue #30 -- one row per session, and an explicit ownership marker.
 *
 * SessionLifecycle wrote with updateOrCreate(['user_id', 'revoked_at' => null]),
 * so a user had at most one live row and a second device REBOUND it rather than
 * adding one. Measured before any of this was written: after two logins the
 * first device's binding was gone from auth_sessions, and a password change
 * from the second device revoked zero sessions. The first device kept full
 * permissions, and there was no row anything could revoke.
 *
 * ValidatesVouchSession passed a session through whenever no record matched,
 * which is what turned that orphan into a live unmanaged session. The
 * pass-through itself is deliberate -- Vouch does not own every host session --
 * so the fix cannot simply refuse the unknown. It has to be able to TELL which
 * unknown sessions were once its own.
 *
 * Hence a marker, and this truth table:
 *
 *   no marker,   no record   -> pass    (a host session Vouch never established)
 *   no marker,   record      -> REFUSE  (established before the marker shipped)
 *   marker,      no record   -> REFUSE  (the record was pruned, deleted or lost)
 *   marker,      revoked     -> REFUSE  (what revocation is for)
 *   marker,      live match  -> pass
 *   marker copied elsewhere  -> REFUSE  (it is bound to one session)
 *
 * The second row is the rollout rule. A session established before this ships
 * carries no marker, and without it nothing separates that session from an
 * ordinary host session -- so the presence of a record is what identifies it,
 * and those sessions are refused rather than silently trusted.
 *
 * The tests never name the marker's key. They drive establish(), which is what
 * production does, and the tampering test copies the WHOLE session payload
 * rather than one field -- which is also the realistic attack.
 */

/** @return list<\Fissible\Vouch\Kernel\Factor\SatisfiedFactor> */
function ownershipFactors(): array
{
    return [evidenceFactor('password', '2026-09-01T10:00:00+00:00')];
}

function ownershipSuccess(int $userId = 7): AuthSuccess
{
    $factors = ownershipFactors();

    return new AuthSuccess(
        userId: $userId,
        factors: $factors,
        facts: AssuranceFacts::fromFactors($factors),
        acr: 'aal1',
        boundContext: 'session',
        tenantId: null,
    );
}

/** A distinct host session, the way a separate device would have one. */
function deviceSession(string $id): Store
{
    $store = new Store('vouch-device', new ArraySessionHandler(120), str_pad($id, 40, 'x'));
    $store->start();

    return $store;
}

/**
 * Establish a Vouch session on this device's store, as a login would.
 *
 * Bound through the container so SessionLifecycle writes into THIS store,
 * which is what makes two devices separable in a single process.
 */
function establishOn(Store $store, int $userId = 7): void
{
    app()->instance(\Illuminate\Contracts\Session\Session::class, $store);
    app()->forgetInstance(SessionLifecycle::class);

    app(SessionLifecycle::class)->establish(ownershipSuccess($userId));
}

function bindingOf(Store $store): string
{
    return SessionBinding::for($store->getId(), BindingDomain::Session);
}

/** Run the middleware against this store and report whether it passed. */
function passesValidation(Store $store): bool
{
    $request = Request::create('/dashboard');
    $request->setLaravelSession($store);

    $reached = false;

    $response = app(ValidatesVouchSession::class)->handle(
        $request,
        function () use (&$reached): Response {
            $reached = true;

            return new Response('ok');
        },
    );

    // Both halves: a refusal must not call the next handler, and must not
    // return 200 pretending it did.
    if (! $reached) {
        expect($response->getStatusCode())->not->toBe(200);
    }

    return $reached;
}

/* ---- the row shape ------------------------------------------------------ */

it('gives each device its own session row', function (): void {
    /*
     * The defect, stated as the fix. Two devices previously shared one row and
     * the first device's binding simply vanished when the second logged in.
     */
    $alpha = deviceSession('alpha');
    establishOn($alpha);
    $alphaBinding = bindingOf($alpha);

    $beta = deviceSession('beta');
    establishOn($beta);

    expect(AuthSession::query()->where('user_id', 7)->whereNull('revoked_at')->count())->toBe(2)
        ->and(AuthSession::query()->where('session_binding', $alphaBinding)->whereNull('revoked_at')->exists())
        ->toBeTrue();
});

it('revokes the other device when one changes its password', function (): void {
    /*
     * What the single-row shape silently stopped doing. revokeSiblings()
     * selects live rows for the user other than the one kept; with one row
     * there was never another, so it revoked nothing and reported zero.
     */
    $alpha = deviceSession('alpha');
    establishOn($alpha);
    $alphaBinding = bindingOf($alpha);

    $beta = deviceSession('beta');
    establishOn($beta);

    $revoked = app(SessionLifecycle::class)->revokeSiblings(7, bindingOf($beta), RevokedReason::PasswordChanged);

    expect($revoked)->toBe(1)
        ->and(AuthSession::query()->where('session_binding', $alphaBinding)->value('revoked_at'))->not->toBeNull();
});

it('refuses the revoked device on its next request', function (): void {
    // Revocation is inert until the middleware reads it; this is the half that
    // makes a password change actually reach the other device.
    $alpha = deviceSession('alpha');
    establishOn($alpha);

    $beta = deviceSession('beta');
    establishOn($beta);

    app(SessionLifecycle::class)->revokeSiblings(7, bindingOf($beta), RevokedReason::PasswordChanged);

    expect(passesValidation($alpha))->toBeFalse()
        ->and(passesValidation($beta))->toBeTrue();
});

it('does not accumulate rows when one device re-authenticates', function (): void {
    /*
     * Per-session rows must not become per-login rows. Re-authenticating
     * regenerates the id, so the device's previous session no longer exists
     * and its row must not stay live -- otherwise a user who logs in daily
     * leaves a growing set of live rows nobody holds.
     */
    $device = deviceSession('alpha');
    establishOn($device);
    $first = bindingOf($device);

    establishOn($device);

    expect($first)->not->toBe(bindingOf($device))
        ->and(AuthSession::query()->where('user_id', 7)->whereNull('revoked_at')->count())->toBe(1)
        ->and(AuthSession::query()->where('session_binding', $first)->value('revoked_at'))->not->toBeNull();
});

/* ---- the ownership marker ----------------------------------------------- */

it('passes a host session Vouch never established', function (): void {
    // The deliberate case the pass-through exists for, and the reason this
    // cannot be fixed by refusing everything unknown.
    $store = deviceSession('stranger');

    expect(passesValidation($store))->toBeTrue();
});

it('passes an established session while its record is live', function (): void {
    $device = deviceSession('alpha');
    establishOn($device);

    expect(passesValidation($device))->toBeTrue();
});

it('refuses an established session whose record has been deleted', function (): void {
    /*
     * The reason the marker exists. Without it a deleted row is
     * indistinguishable from a session Vouch never saw, so retention, a manual
     * cleanup or a bug silently RESTORES access instead of ending it.
     */
    $device = deviceSession('alpha');
    establishOn($device);

    AuthSession::query()->where('session_binding', bindingOf($device))->delete();

    expect(passesValidation($device))->toBeFalse();
});

it('refuses a session established before the marker shipped', function (): void {
    /*
     * The rollout rule. Such a session has a record but no marker, and nothing
     * else separates it from an ordinary host session -- so the record is what
     * identifies it, and it is refused rather than trusted.
     *
     * Simulated by clearing the session payload while leaving the row, which is
     * exactly the state an upgrade produces.
     */
    $device = deviceSession('alpha');
    establishOn($device);
    $binding = bindingOf($device);

    $device->flush();

    expect(AuthSession::query()->where('session_binding', $binding)->whereNull('revoked_at')->exists())->toBeTrue()
        ->and(passesValidation($device))->toBeFalse();
});

it('refuses a marker copied into another session', function (): void {
    /*
     * The marker is bound to one session, so lifting it does not carry
     * authority with it. The whole payload is copied rather than one field --
     * both because that is the realistic attack and because naming the field
     * would pin an implementation detail these tests deliberately avoid.
     */
    $device = deviceSession('alpha');
    establishOn($device);

    $thief = deviceSession('thief');

    foreach ($device->all() as $key => $value) {
        $thief->put($key, $value);
    }

    // The theft copied something, or this test proves nothing about copying.
    expect($device->all())->not->toBe([]);

    expect(passesValidation($thief))->toBeFalse();
});

it('keeps the marker valid across the rotation establish performs', function (): void {
    /*
     * establish() regenerates the session id before writing, and a step-up
     * establishes again on a live session. A marker that survived neither would
     * lock a user out of their own session at the moment their assurance rose.
     */
    $device = deviceSession('alpha');
    establishOn($device);

    expect(passesValidation($device))->toBeTrue();

    establishOn($device);

    expect(passesValidation($device))->toBeTrue();
});

it('marks nothing when establishing fails', function (): void {
    /*
     * A marker written before the row would claim ownership of a session that
     * never got one -- and by the truth table above, a marker with no record is
     * refused. A user would then be locked out by a failure that had left them
     * unauthenticated anyway.
     *
     * The failure is injected at the vocabulary, which establish() calls inside
     * its own try before the write. Dropping the table instead would fight
     * RefreshDatabase's transaction and fail for a reason unrelated to markers.
     */
    $device = deviceSession('alpha');

    app()->instance(\Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary::class, new class implements \Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary
    {
        public function name(\Fissible\Vouch\Kernel\Assurance\AssuranceFacts $facts): string
        {
            throw new RuntimeException('the vocabulary failed while establishing');
        }
    });

    try {
        establishOn($device);
        $threw = false;
    } catch (Throwable) {
        $threw = true;
    }

    // The failure landed where this test believes it did.
    expect($threw)->toBeTrue()
        ->and(AuthSession::query()->count())->toBe(0);

    /*
     * No record and no marker, so this reads as an ordinary host session rather
     * than a Vouch session whose row went missing. Establishing must not leave
     * a claim behind when it did not finish.
     */
    expect(passesValidation($device))->toBeTrue();
});
