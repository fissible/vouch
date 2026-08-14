<?php

declare(strict_types=1);

use Fissible\Vouch\Recovery\GraceController;
use Fissible\Vouch\Recovery\GraceGuard;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * GraceController had NO coverage at all -- 23 uncovered mutations, the whole
 * file. These are the endpoints that decide what a stolen recovery code can
 * still do, so "uncovered" here is not a gap in a helper.
 */

function graceSessionId(string $label): string
{
    // Store::setId() silently discards anything that is not 40 alphanumeric
    // characters and generates a random one instead -- so a readable label never
    // reaches the query and the controller looks like it refused when it simply
    // never saw the row.
    return substr(str_pad((string) preg_replace('/[^a-zA-Z0-9]/', '', $label), 40, 'x'), 0, 40);
}

function graceRequest(string $sessionId): Request
{
    $store = new Store('vouch_grace_session', new ArraySessionHandler(120), $sessionId);
    $store->start();

    $request = Request::create('/vouch/recovery/enroll', 'POST');
    $request->setLaravelSession($store);

    return $request;
}

function graceController(): GraceController
{
    return app(GraceController::class);
}

it('reports grace active while the capability is live', function (string $method): void {
    $id = graceSessionId('live-grace');
    app(GraceGuard::class)->start($id, 7);

    $response = graceController()->{$method}(graceRequest($id));

    expect($response->getStatusCode())->toBe(200)
        ->and($response->getData(true))->toBe(['result' => 'grace_active']);
})->with(['enroll', 'complete']);

it('reports grace expired when there is no capability at all', function (string $method): void {
    /*
     * A request with no grace row must not be treated as in-grace. Same status,
     * different result -- the single-200 rule means the outcome is carried by the
     * body, so the body is the security-relevant part of the response.
     */
    $response = graceController()->{$method}(graceRequest(graceSessionId('no-grace')));

    expect($response->getStatusCode())->toBe(200)
        ->and($response->getData(true))->toBe(['result' => 'grace_expired']);
})->with(['enroll', 'complete']);

it('expires a lapsed capability before answering, not after', function (string $method): void {
    /*
     * expireIfLapsed() runs first, and it is a mutation rather than a read. A row
     * live when the request arrived can lapse before this point, and enrollment
     * during grace is itself a mutation -- so answering from a stale read would
     * let a lapsed capability perform one last privileged action.
     *
     * The row must also be RECORDED as expired, not merely reported so: the
     * revocation reason is what distinguishes a lapse from an admin revocation
     * afterwards.
     */
    $id = graceSessionId('lapsed-grace');

    AuthSession::create([
        'session_binding' => SessionBinding::for($id, BindingDomain::Session),
        'user_id' => 7,
        'amr' => ['recovery_code'],
        'recovery_grace_expires_at' => now()->subMinute(),
    ]);

    $response = graceController()->{$method}(graceRequest($id));
    $row = AuthSession::firstOrFail();

    expect($response->getData(true))->toBe(['result' => 'grace_expired'])
        ->and($row->revoked_at)->not->toBeNull()
        ->and($row->revoked_reason)->toBe(RevokedReason::GraceExpired);
})->with(['enroll', 'complete']);

it('does not treat another session grace as this one', function (string $method): void {
    // The binding is per host session. A live capability belonging to someone
    // else must not answer for this request.
    app(GraceGuard::class)->start(graceSessionId('someone-else'), 7);

    $response = graceController()->{$method}(graceRequest(graceSessionId('this-session')));

    expect($response->getData(true))->toBe(['result' => 'grace_expired']);
})->with(['enroll', 'complete']);
