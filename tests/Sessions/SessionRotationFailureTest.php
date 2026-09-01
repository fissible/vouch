<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Fissible\Vouch\Sessions\SessionRotationFailed;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Schema;

/*
 * DatabaseMigrations, NOT RefreshDatabase, and its own file.
 *
 * This test drops a table to force the record write to fail. MySQL implicitly
 * commits on DDL, so under RefreshDatabase the drop would silently end the
 * wrapping transaction and Laravel's later rollback would throw
 * "SAVEPOINT trans2 does not exist" -- a harness failure masquerading as the
 * assertion. Phase 2.2 hit exactly this and split EnrollmentGuardErrorsTest out
 * for the same reason.
 */
uses(DatabaseMigrations::class);

it('destroys the regenerated session and fails closed when the record cannot be written', function (): void {
    /*
     * The branch that matters most in the whole protocol. Untested, it is the
     * one that leaves a user guard-authenticated with no vouch record -- a
     * session that passes every host check and fails vouch's per-request read
     * for as long as it lives.
     */
    session()->start();
    $before = session()->getId();

    /*
     * A marker, because asserting only that the session ID changed is VACUOUS:
     * regenerate() already changed it BEFORE the write failed, so that
     * assertion passes whether or not invalidate() ever runs. invalidate()
     * flushes the session contents, so the marker's absence is what actually
     * distinguishes "destroyed" from "merely regenerated".
     */
    session()->put('vouch.probe.marker', 'present');

    Schema::drop('auth_sessions');

    $factor = new SatisfiedFactor('password', '7', FactorKind::Knowledge, FactorStrength::Knowledge,
        false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'));

    try {
        app(SessionLifecycle::class)->establish(
            new AuthSuccess(7, [$factor], AssuranceFacts::fromFactors([$factor]), 'aal1', 'ignored', null),
        );
        $this->fail('Expected SessionRotationFailed.');
    } catch (SessionRotationFailed) {
        // expected
    }

    expect(session()->getId())->not->toBe($before)
        ->and(session()->has('vouch.probe.marker'))->toBeFalse();
});
