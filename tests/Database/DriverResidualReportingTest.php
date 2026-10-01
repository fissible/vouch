<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Credentials\CredentialDriverFailure;
use Fissible\Vouch\Credentials\CredentialDriverFailureCollector;
use Fissible\Vouch\Credentials\CredentialDriverFailureIdentity;
use Fissible\Vouch\Credentials\CredentialMutation;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor;
use Fissible\Vouch\Factors\Drivers\TotpFactor;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\SelfService\CredentialSelfService;
use Fissible\Vouch\SelfService\SelfServiceOutcome;
use Fissible\Vouch\SelfService\SelfServiceResult;
use Fissible\Vouch\Tests\Support\CompanionRetiringFactor;
use Fissible\Vouch\Tests\Support\DeferredIssuerProbe;
use Fissible\Vouch\Tests\Support\CompanionRevokingFactor;
use Fissible\Vouch\Tests\Support\InterceptingFactor;
use Fissible\Vouch\Tests\Support\InterceptingPasswordFactor;
use Fissible\Vouch\Tests\Support\SelfReportingFactor;
use Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Tokens\TokenIssuerRegistry;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;

uses(DatabaseMigrations::class);

/*
 * #35, third pass. Who learns that a token was left live at its issuer.
 *
 * The services now report the driver failures from their own revocation pass.
 * The gap measured afterwards is one layer down: a proof created between the
 * service's credential-id list and the factor's own is withdrawn correctly by
 * CredentialMutation's snapshot union, but the failure its issuer then reports
 * lands on a result the factor discarded. The operation returned a clean
 * Completed while that token may still be authenticating.
 *
 * Two things are frozen here, and they pull against each other, which is why
 * they belong in one file.
 *
 * The identity must travel: out of the factor, into the service's result,
 * merged with the pre-pass and de-duplicated so a token revoked successfully in
 * either pass never appears.
 *
 * The DIAGNOSTIC must not. CredentialMutation's internal failure keeps the
 * driver's exception text and its own tests require that. Whatever channel
 * carries the identity out must not carry the text with it -- a driver's error
 * string on a caller's result can reach a response body or a log the operator
 * did not choose. The first implementation of this handed the internal result
 * object to EnrollmentResult, which put the text within reach of anyone calling
 * a factor directly. That is the same leak through a different door.
 *
 * DatabaseMigrations, not RefreshDatabase: driver callbacks run at COMMIT, so a
 * wrapper transaction that never commits would mean they never run at all.
 */

const RESIDUAL_SENTINEL = 'SENTINEL-DIAGNOSTIC-a1b2c3';

function residualUser(int $userId = 1): void
{
    app(PasswordFactor::class)->enroll($userId, ['password' => 'old-password']);
}

function residualSession(string $binding = 'residual-1'): AuthSession
{
    return AuthSession::create([
        'user_id' => 1,
        'session_binding' => str_pad($binding, 64, 'r'),
        'amr' => ['pwd', 'otp'],
        'acr' => 'aal2',
        'assurance_proof' => sessionProof(1, 'aal2'),
        'weakest_satisfied_at' => now(),
    ]);
}

/** Seed a human token whose recorded proof cites one credential. */
function residualToken(string $tokenKey, string $type, int $credentialId, int $userId = 1): void
{
    app(TokenAssuranceRecord::class)->store(
        'sanctum',
        $tokenKey,
        SubjectKey::forConfiguredUser($userId),
        null,
        ActorKind::Human,
        [new SatisfiedFactor(
            $type,
            (string) $credentialId,
            $type === 'password' ? FactorKind::Knowledge : FactorKind::Possession,
            $type === 'password' ? FactorStrength::Knowledge : FactorStrength::Possession,
            false, false, false, null,
            new DateTimeImmutable('2026-08-13T10:00:00+00:00'),
        )],
    );
}

/**
 * An issuer whose revoke() fails for each of $failing, with a recognisable text.
 *
 * @param list<string> $failing
 */
function residualIssuer(array $failing = ['late']): RecordingIssuer
{
    $issuer = new RecordingIssuer('sanctum');
    $issuer->onRevoke = function () use (&$issuer, $failing): null {
        if (in_array(end($issuer->attempted), $failing, true)) {
            throw new RuntimeException(RESIDUAL_SENTINEL);
        }

        return null;
    };

    app()->instance(TokenIssuerRegistry::class, new TokenIssuerRegistry([$issuer]));
    app()->forgetInstance(CredentialSelfService::class);

    return $issuer;
}

/** Write an enabled credential directly, outside any factor's own list. */
function lateCredential(string $type, string $secret = 'late-digest', int $userId = 1): AuthCredential
{
    return AuthCredential::create([
        'user_id' => $userId,
        'type' => $type,
        'secret' => $secret,
        'strength' => $type === 'totp' ? 'possession' : 'recovery',
    ]);
}

/**
 * The identities a result reports, as sorted (issuer, token) pairs.
 *
 * Typed against the real identity rather than object: at level 9 a bare object
 * has no properties to read, and loosening the assertion to get past that would
 * stop it noticing if the channel started carrying something else.
 *
 * @param list<CredentialDriverFailureIdentity> $failures
 * @return list<array{string, string}>
 */
function residualPairs(array $failures): array
{
    $pairs = array_map(
        static fn (CredentialDriverFailureIdentity $failure): array => [$failure->issuerKey, $failure->tokenKey],
        $failures,
    );
    sort($pairs);

    return $pairs;
}

/* ---- the diagnostic must not travel with the identity ----------------- */

it('keeps a driver diagnostic out of what enrollment hands back', function (string $factor): void {
    residualUser();

    /*
     * The cited credential has to be one this enrollment REPLACES, or the
     * enrollment is additive and revokes nothing. Recovery-code enrollment is
     * additive until a set already exists, which is why it gets one here.
     */
    if ($factor === 'password') {
        $cited = AuthCredential::query()->where('user_id', 1)->where('type', 'password')->firstOrFail();
    } else {
        $cited = app(RecoveryCodeFactor::class)->enroll(1, [])->credentials[0];
    }
    residualToken('late', $factor, $cited->id);

    $issuer = residualIssuer();

    /*
     * Called DIRECTLY, not through the service. Factor::enroll() is public API,
     * so whatever the factor returns is a caller's result too -- and it did not
     * expose the driver's text before this work, so it must not after it.
     */
    $enrollment = $factor === 'password'
        ? app(PasswordFactor::class)->enroll(1, ['password' => 'new-password', 'replace' => true])
        : app(RecoveryCodeFactor::class)->enroll(1, []);

    expect($issuer->attempted)->toContain('late')
        // print_r walks nested public properties, so it catches the text
        // wherever on the object graph it was parked.
        ->and(print_r($enrollment, true))->not->toContain(RESIDUAL_SENTINEL)
        ->and(json_encode($enrollment))->not->toContain(RESIDUAL_SENTINEL);
})->with(['password', 'recovery_code']);

it('still reports the identity once the enclosing transaction commits', function (): void {
    residualUser();
    $existing = AuthCredential::query()->where('user_id', 1)->where('type', 'password')->firstOrFail();
    residualToken('late', 'password', $existing->id);

    $issuer = residualIssuer();

    /*
     * Inside a caller's transaction the driver work defers to the OUTERMOST
     * commit by design, so the identity cannot be read before this closure
     * returns. A channel that snapshots at construction reports nothing here
     * while reporting correctly standalone.
     */
    $enrollment = DB::transaction(
        fn () => app(PasswordFactor::class)->enroll(1, ['password' => 'new-password', 'replace' => true]),
    );

    expect($issuer->attempted)->toContain('late')
        ->and(residualPairs($enrollment->driverFailures))->toBe([['sanctum', 'late']])
        ->and(print_r($enrollment->driverFailures, true))->not->toContain(RESIDUAL_SENTINEL);
});

/* ---- the identity must travel, from every path that can strand one ---- */

it('reports a proof withdrawn late by a replacement', function (): void {
    residualUser();
    $totp = app(TotpFactor::class)->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    residualToken('early', 'totp', $totp->id);

    $issuer = residualIssuer();

    /*
     * before() runs after the service took its credential-id list and before
     * the factor takes its own, so this credential is in the factor's list
     * only. Replacement is the second path that can strand a proof this way;
     * the frozen regeneration test covers the first.
     */
    $factor = new InterceptingPasswordFactor(
        app(TotpFactor::class),
        before: function (): null {
            residualToken('late', 'totp', lateCredential('totp', 'JBSWY3DPEHPK3PXP')->id);

            return null;
        },
    );
    $registry = new FactorRegistry();
    $registry->register(app(PasswordFactor::class));
    $registry->register($factor);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);

    $result = app(CredentialSelfService::class)
        ->addFactor(residualSession(), 'totp', ['label' => 'ada@acme.example', 'replace' => true]);

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->secrets)->not->toBe([])
        ->and(DB::table('auth_token_assurances')->where('token_key', 'late')->exists())->toBeFalse()
        // 'early' was revoked successfully in the pre-pass, so naming it would
        // send an operator after a token that is already gone.
        ->and(residualPairs($result->driverFailures))->toBe([['sanctum', 'late']])
        ->and(print_r($result->driverFailures, true))->not->toContain(RESIDUAL_SENTINEL);
});

it('reports a proof withdrawn late by a removal', function (string $type, string $secret): void {
    residualUser();
    $target = lateCredential($type, $secret);
    $untargeted = lateCredential($type, $secret . '-other');
    residualToken('untargeted', $type, $untargeted->id);

    $issuer = residualIssuer();

    /*
     * Removal names one credential, so the service's pre-pass withdrew the
     * proofs citing it and finished. A proof created after that, still citing
     * the target, is withdrawn by the factor's own mutation -- and its failure
     * had nowhere to go, because revoke() returns void.
     */
    $factor = new InterceptingFactor(
        app($type === 'totp' ? TotpFactor::class : RecoveryCodeFactor::class),
        beforeRevoke: function () use ($target): null {
            residualToken('late', $target->type, $target->id);

            return null;
        },
    );
    $registry = new FactorRegistry();
    $registry->register(app(PasswordFactor::class));
    $registry->register($factor);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);

    $result = app(CredentialSelfService::class)->removeFactor(residualSession(), $target->id);

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and(AuthCredential::query()->whereKey($target->id)->whereNull('disabled_at')->exists())->toBeFalse()
        ->and(DB::table('auth_token_assurances')->where('token_key', 'late')->exists())->toBeFalse()
        ->and(residualPairs($result->driverFailures))->toBe([['sanctum', 'late']])
        ->and(print_r($result->driverFailures, true))->not->toContain(RESIDUAL_SENTINEL)
        /*
         * The preservation control. A removal that widened its sweep to catch
         * the late proof would take this untargeted credential's proof with it,
         * and would then also report a failure this test forbids.
         */
        ->and(AuthCredential::query()->whereKey($untargeted->id)->whereNull('disabled_at')->exists())->toBeTrue()
        ->and(DB::table('auth_token_assurances')->where('token_key', 'untargeted')->exists())->toBeTrue();
})->with([
    'totp' => ['totp', 'JBSWY3DPEHPK3PXP'],
    'recovery_code' => ['recovery_code', 'digest'],
]);

/*
 * #53. A custom factor's revoke() may perform more than one mutation, and only
 * the first one's issuer failures reached the caller.
 *
 * The writes were always correct: every mutation ran, every credential was
 * disabled, every proof withdrawn. What stopped short was the reporting, and that
 * is the worse half -- the result could say driver cleanup was clean while a token
 * from the second mutation was still live at its issuer. That is exactly the defect
 * removed from the shipped paths, surviving on the extension contract.
 *
 * No shipped factor triggers it: password, TOTP, recovery code and the OTP drivers
 * each perform exactly one mutation. So the tests below need a factor of their own,
 * and the shape they use is an ordinary one -- retiring a companion credential
 * alongside the requested one.
 *
 * Measured, the defect is worse than "only the first mutation is reported". A custom
 * factor for a TOTP credential still has to revoke that credential, so it delegates
 * to the shipped driver -- whose own mutation is then the FIRST, claims the report
 * channel, and leaves every one of the custom factor's own mutations excluded. The
 * list comes back empty rather than short, with every premise holding: both
 * mutations ran, both revocations were attempted, both credentials were disabled and
 * both proofs withdrawn.
 *
 * The hard part is that a SEQUENTIAL second mutation and a NESTED foreign one look
 * identical from the collector's side: both are "another mutation on this
 * connection during the collected call". The exclusions in
 * 'keeps an unrelated mutation out of a removal's residual' above are the other
 * half of this contract and must keep holding -- an observer's mutation, whether
 * for a different subject or the same subject's different credential, stays out.
 * Widening the collector until the tests below pass, without keeping those green,
 * would trade a missing report for a false one.
 */

it('reports failures from every mutation a factor performs, not only the first', function (): void {
    residualUser();

    $target = lateCredential('totp', 'JBSWY3DPEHPK3PXP');
    $first = lateCredential('totp', 'JBSWY3DPEHPK3PXP-first');
    $second = lateCredential('totp', 'JBSWY3DPEHPK3PXP-second');

    $issuer = residualIssuer(['late-first', 'late-second']);

    /*
     * Each proof is created immediately before the mutation that withdraws it, so
     * both are later than the service's own revocation pass and neither could have
     * been caught by it. That is what makes the second mutation the only possible
     * source of the second identity.
     */
    $factor = new CompanionRevokingFactor(
        app(TotpFactor::class),
        [
            ['id' => $first->id, 'before' => function () use ($first): void {
                residualToken('late-first', 'totp', $first->id);
            }],
            ['id' => $second->id, 'before' => function () use ($second): void {
                residualToken('late-second', 'totp', $second->id);
            }],
        ],
    );

    $registry = new FactorRegistry();
    $registry->register(app(PasswordFactor::class));
    $registry->register($factor);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);

    $result = app(CredentialSelfService::class)->removeFactor(residualSession(), $target->id);

    /*
     * Premises first, each on its own expectation. A chain that asserts the
     * conclusion early stops there and says nothing about whether the setup even
     * held -- and the first run of this test returned an empty list, which could
     * equally have meant "reporting is broken" or "no revocation was attempted".
     */
    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    // Entered, in order. Recorded before each revoking() call, so completion is what
    // the disabled_at assertions below establish rather than this one.
    expect($factor->mutated)->toBe([$first->id, $second->id], 'both mutations should have been entered, in order');
    /*
     * ATTEMPTED, not revoked: both of these are configured to fail, so neither can
     * appear among the successes. Asserting the wrong one of the two read as "no
     * revocation happened" when the truth was "both were tried and both failed",
     * which is the premise this test needs.
     */
    /*
     * No failure message on toContain: it is VARIADIC, so a second argument becomes
     * another value the array must contain, and the test then fails looking for the
     * message text. Same shape as toThrow(Throwable::class) asserting on a message.
     */
    expect($issuer->attempted)->toContain('late-first');
    expect($issuer->attempted)->toContain('late-second');

    // The writes were never the defect, and a fix that broke them would be worse.
    expect(AuthCredential::query()->whereKey($first->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect(AuthCredential::query()->whereKey($second->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect(DB::table('auth_token_assurances')->where('token_key', 'late-first')->exists())->toBeFalse();
    expect(DB::table('auth_token_assurances')->where('token_key', 'late-second')->exists())->toBeFalse();

    // And only then the claim: BOTH identities reach the caller.
    expect(residualPairs($result->driverFailures))
        ->toBe([['sanctum', 'late-first'], ['sanctum', 'late-second']]);
});

it('reports the second mutation when only the second fails', function (): void {
    residualUser();

    $target = lateCredential('totp', 'JBSWY3DPEHPK3PXP');
    $first = lateCredential('totp', 'JBSWY3DPEHPK3PXP-first');
    $second = lateCredential('totp', 'JBSWY3DPEHPK3PXP-second');

    /*
     * Only the second token's revocation fails. This is the case that distinguishes
     * a real fix from one that merely returns the FIRST mutation's report under a
     * new name: here the first mutation has nothing to report, so an implementation
     * still bound to it hands back an empty list and calls the cleanup clean while
     * a token is live at its issuer.
     */
    $issuer = residualIssuer(['late-second']);

    $factor = new CompanionRevokingFactor(
        app(TotpFactor::class),
        [
            ['id' => $first->id, 'before' => function () use ($first): void {
                residualToken('late-first', 'totp', $first->id);
            }],
            ['id' => $second->id, 'before' => function () use ($second): void {
                residualToken('late-second', 'totp', $second->id);
            }],
        ],
    );

    $registry = new FactorRegistry();
    $registry->register(app(PasswordFactor::class));
    $registry->register($factor);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);

    $result = app(CredentialSelfService::class)->removeFactor(residualSession(), $target->id);

    /*
     * Premises first here too. This test's failure mode is an empty list, and a
     * chain that asserts that first tells you nothing about whether the first
     * companion ran at all -- which is the diagnosis problem the comment in the
     * test above is about, and which this test had.
     */
    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);

    // The first token really was revoked, so its absence from the list below is a
    // success rather than a second thing going unreported.
    expect($issuer->revoked)->toContain('late-first');
    expect(DB::table('auth_token_assurances')->where('token_key', 'late-first')->exists())->toBeFalse();

    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'late-second']]);
});

it('keeps a driver diagnostic out of what a multi-mutation removal hands back', function (): void {
    residualUser();

    $target = lateCredential('totp', 'JBSWY3DPEHPK3PXP');
    $companion = lateCredential('totp', 'JBSWY3DPEHPK3PXP-companion');

    residualIssuer(['late-companion']);

    /*
     * Identities only, through every route a caller could read the result by. The
     * enrollment path is already held to this; widening the collector to carry a
     * second mutation's failures must not carry its driver text along with them.
     *
     * print_r and json_encode both, because they disagree: json_encode consults
     * JsonSerializable and print_r does not, so a diagnostic hidden from one can
     * still be reachable through the other.
     */
    $factor = new CompanionRevokingFactor(
        app(TotpFactor::class),
        [
            ['id' => $companion->id, 'before' => function () use ($companion): void {
                residualToken('late-companion', 'totp', $companion->id);
            }],
        ],
    );

    $registry = new FactorRegistry();
    $registry->register(app(PasswordFactor::class));
    $registry->register($factor);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);

    $result = app(CredentialSelfService::class)->removeFactor(residualSession(), $target->id);

    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'late-companion']])
        ->and(print_r($result->driverFailures, true))->not->toContain(RESIDUAL_SENTINEL)
        ->and(json_encode($result, JSON_THROW_ON_ERROR))->not->toContain(RESIDUAL_SENTINEL)
        ->and(print_r($result, true))->not->toContain(RESIDUAL_SENTINEL);
});

it('keeps a nested mutation out of a removal residual when no event delivered it', function (): void {
    residualUser();

    $target = lateCredential('totp', 'JBSWY3DPEHPK3PXP');
    $unrelated = lateCredential('totp', 'JBSWY3DPEHPK3PXP-other');

    $issuer = residualIssuer(['target-late', 'unrelated']);

    // Assigned by the hook below, which the first assertion proves ran.
    $nested = null;
    $fired = false;

    /*
     * beforeExecuting(), not an Eloquent observer. Same window, same
     * contamination, different delivery -- and the delivery must not be what
     * the exclusion depends on.
     *
     * @param list<mixed> $bindings
     */
    DB::connection()->beforeExecuting(function (string $query, array $bindings) use (
        &$nested, &$fired, $target, $unrelated
    ): void {
        if ($fired) {
            return;
        }

        $values = array_map(
            static fn (mixed $binding): string => is_scalar($binding) ? (string) $binding : '',
            $bindings,
        );

        // The credential UPDATE that disables the removal's target.
        if (! str_contains(strtolower($query), 'update')
            || ! str_contains(strtolower($query), 'auth_credentials')
            || ! in_array((string) $target->id, $values, true)) {
            return;
        }

        $fired = true;

        residualToken('target-late', 'totp', $target->id);
        residualToken('unrelated', 'totp', $unrelated->id);

        $nested = app(CredentialMutation::class)->revoking(
            SubjectKey::forConfiguredUser(1),
            [(string) $unrelated->id],
            static fn (): null => null,
        );
    });

    $result = app(CredentialSelfService::class)->removeFactor(residualSession(), $target->id);

    $nestedResult = $nested ?? throw new RuntimeException('The beforeExecuting hook never ran a mutation.');

    expect($fired)->toBeTrue();
    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($issuer->attempted)->toContain('target-late');
    expect($issuer->attempted)->toContain('unrelated');
    expect(internalPairs($nestedResult->driverFailures))->toBe([['sanctum', 'unrelated']]);
    expect(DB::table('auth_token_assurances')->where('token_key', 'unrelated')->exists())->toBeFalse();

    // The conclusion: the removal must not name a token it never touched.
    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'target-late']]);
});

it('keeps an observer mutation that disables its own credential out of the residual', function (): void {
    residualUser();

    $target = lateCredential('totp', 'JBSWY3DPEHPK3PXP');
    $unrelated = lateCredential('totp', 'JBSWY3DPEHPK3PXP-other');

    $issuer = residualIssuer(['target-late', 'unrelated']);

    // Assigned by the observer below, which the first assertion proves ran.
    $nested = null;
    $fired = false;

    AuthCredential::updating(function (AuthCredential $credential) use (
        &$nested, &$fired, $target, $unrelated
    ): void {
        if ($fired || $credential->id !== $target->id) {
            return;
        }
        $fired = true;

        residualToken('target-late', 'totp', $target->id);
        residualToken('unrelated', 'totp', $unrelated->id);

        /*
         * An ordinary host cascade: retire a companion of its own when a
         * credential is disabled. Its mutation WRITES, which is the half the
         * inert observer elsewhere in this file never exercises.
         */
        $nested = app(CredentialMutation::class)->revoking(
            SubjectKey::forConfiguredUser(1),
            [(string) $unrelated->id],
            static function () use ($unrelated): null {
                AuthCredential::query()->whereKey($unrelated->id)->update(['disabled_at' => now()]);

                return null;
            },
        );
    });

    $result = app(CredentialSelfService::class)->removeFactor(residualSession(), $target->id);

    $nestedResult = $nested ?? throw new RuntimeException('The updating observer never ran.');

    expect($fired)->toBeTrue();
    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($issuer->attempted)->toContain('target-late');
    expect($issuer->attempted)->toContain('unrelated');
    expect(internalPairs($nestedResult->driverFailures))->toBe([['sanctum', 'unrelated']]);
    expect(DB::table('auth_token_assurances')->where('token_key', 'unrelated')->exists())->toBeFalse();
    // The observer's own work really happened; it is the observer's to report.
    expect(AuthCredential::query()->whereKey($unrelated->id)->whereNull('disabled_at')->exists())->toBeFalse();

    // The conclusion: the removal still names only the token it touched.
    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'target-late']]);
});

it('reports every companion and still excludes a nested observer in the same call', function (): void {
    residualUser();

    $target = lateCredential('totp', 'JBSWY3DPEHPK3PXP');
    $first = lateCredential('totp', 'JBSWY3DPEHPK3PXP-first');
    $second = lateCredential('totp', 'JBSWY3DPEHPK3PXP-second');
    $unrelated = lateCredential('totp', 'JBSWY3DPEHPK3PXP-other');

    $issuer = residualIssuer(['late-first', 'late-second', 'unrelated']);

    // Assigned by the observer below, which the first assertion proves ran.
    $nested = null;
    $fired = false;

    AuthCredential::updating(function (AuthCredential $credential) use (
        &$nested, &$fired, $target, $unrelated
    ): void {
        if ($fired || $credential->id !== $target->id) {
            return;
        }
        $fired = true;

        residualToken('unrelated', 'totp', $unrelated->id);

        $nested = app(CredentialMutation::class)->revoking(
            SubjectKey::forConfiguredUser(1),
            [(string) $unrelated->id],
            static fn (): null => null,
        );
    });

    $factor = new CompanionRevokingFactor(
        app(TotpFactor::class),
        [
            ['id' => $first->id, 'before' => function () use ($first): void {
                residualToken('late-first', 'totp', $first->id);
            }],
            ['id' => $second->id, 'before' => function () use ($second): void {
                residualToken('late-second', 'totp', $second->id);
            }],
        ],
    );

    $registry = new FactorRegistry();
    $registry->register(app(PasswordFactor::class));
    $registry->register($factor);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);

    $result = app(CredentialSelfService::class)->removeFactor(residualSession(), $target->id);

    $nestedResult = $nested ?? throw new RuntimeException('The updating observer never ran.');

    expect($fired)->toBeTrue();
    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($factor->mutated)->toBe([$first->id, $second->id], 'both companion mutations should have run');
    expect($issuer->attempted)->toContain('late-first');
    expect($issuer->attempted)->toContain('late-second');
    expect($issuer->attempted)->toContain('unrelated');
    expect(internalPairs($nestedResult->driverFailures))->toBe([['sanctum', 'unrelated']]);
    expect(AuthCredential::query()->whereKey($unrelated->id)->whereNull('disabled_at')->exists())->toBeTrue();
    expect(DB::table('auth_token_assurances')->where('token_key', 'unrelated')->exists())->toBeFalse();

    // Both halves at once: every companion named, the observer's token not.
    expect(residualPairs($result->driverFailures))
        ->toBe([['sanctum', 'late-first'], ['sanctum', 'late-second']]);
});

/**
 * The identities an internal mutation result reports, as sorted pairs.
 *
 * The internal type keeps the driver's text; only the identities are compared,
 * which is what the two results have in common.
 *
 * @param list<CredentialDriverFailure> $failures
 * @return list<array{string, string}>
 */
function internalPairs(array $failures): array
{
    $pairs = array_map(
        static fn (CredentialDriverFailure $failure): array => [$failure->issuerKey, $failure->tokenKey],
        $failures,
    );
    sort($pairs);

    return $pairs;
}

it('keeps an unrelated mutation out of a removal\'s residual', function (int $unrelatedUser): void {
    residualUser();
    if ($unrelatedUser !== 1) {
        residualUser($unrelatedUser);
    }

    $target = lateCredential('totp', 'JBSWY3DPEHPK3PXP');
    $unrelated = lateCredential('totp', 'JBSWY3DPEHPK3PXP-other', $unrelatedUser);

    $issuer = residualIssuer(['target-late', 'unrelated']);

    /*
     * The window is not hypothetical. Disabling the target fires Eloquent's
     * updating event, and an observer there can run a second mutation on the
     * same connection -- measured, not imagined.
     *
     * A channel that matches on the connection alone hands that mutation's
     * failure to the removal, which then names a token it never touched. The
     * same-subject row is the one that matters most: matching on the subject as
     * well as the connection still gets it wrong, because both operations
     * belong to the same user.
     */
    // Assigned by the observer below, which the first assertion proves ran.
    $nested = null;
    $fired = false;

    AuthCredential::updating(function (AuthCredential $credential) use (
        &$nested, &$fired, $target, $unrelated, $unrelatedUser
    ): void {
        if ($fired || $credential->id !== $target->id) {
            return;
        }
        $fired = true;

        residualToken('target-late', 'totp', $target->id);
        residualToken('unrelated', 'totp', $unrelated->id, $unrelatedUser);

        $nested = app(CredentialMutation::class)->revoking(
            SubjectKey::forConfiguredUser($unrelatedUser),
            [(string) $unrelated->id],
            static fn (): null => null,
        );
    });

    $result = app(CredentialSelfService::class)->removeFactor(residualSession(), $target->id);

    /*
     * Fail loudly rather than compare an empty list: if the observer never ran,
     * there was no competing mutation and every isolation assertion below would
     * pass while proving nothing.
     */
    $nestedResult = $nested ?? throw new RuntimeException('The updating observer never ran.');

    expect($fired)->toBeTrue()
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        // Each operation reports its own, and only its own.
        ->and(residualPairs($result->driverFailures))->toBe([['sanctum', 'target-late']])
        ->and(internalPairs($nestedResult->driverFailures))->toBe([['sanctum', 'unrelated']])
        /*
         * Both revocations must still have been attempted and both proofs
         * withdrawn. Excluding the unrelated failure by suppressing the nested
         * mutation would satisfy the two assertions above while silently
         * cancelling work that was asked for.
         */
        ->and($issuer->attempted)->toContain('target-late')
        ->and($issuer->attempted)->toContain('unrelated')
        ->and(DB::table('auth_token_assurances')->where('token_key', 'target-late')->exists())->toBeFalse()
        ->and(DB::table('auth_token_assurances')->where('token_key', 'unrelated')->exists())->toBeFalse()
        ->and(AuthCredential::query()->whereKey($target->id)->whereNull('disabled_at')->exists())->toBeFalse()
        ->and(AuthCredential::query()->whereKey($unrelated->id)->whereNull('disabled_at')->exists())->toBeTrue();
})->with([
    'different subject' => [2],
    'same subject, different credential' => [1],
]);

/*
 * #77. The enroll side of the same defect, in two distinct shapes.
 *
 * SHAPE ONE -- only one mutation's failures can travel. `EnrollmentResult` carries
 * exactly one CredentialDriverFailureReport, so a factor whose enroll() performs
 * more than one mutation can hand back at most one of their reports. Every shipped
 * driver performs exactly one, so every shipped path is correct today; the loss is
 * on the extension contract, and it is silent -- the result says the cleanup was
 * clean while a token from the later mutation is still live at its issuer.
 *
 * It is not fixable on the driver's side. A factor cannot forward the reports it
 * did not create (the property is private, and only the identity list is readable),
 * and it cannot rebuild one from identities either, because driver revocation runs
 * at afterCommit -- for a nested mutation, the CALLER's outermost commit, after
 * enroll() has already returned. 'it still reports the identity once the enclosing
 * transaction commits' above is the same fact seen from the shipped side. So the
 * live channel has to be the caller's, which is what removal already does.
 *
 * SHAPE TWO -- addFactor() without `replace` discards driverFailures outright.
 * That branch returns early, bypassing mutateCredentials(), and builds its
 * SelfServiceResult from the secrets alone. It is not a custom-factor-only defect:
 * RecoveryCodeFactor::enroll() disables the existing active set unconditionally,
 * with no `replace` flag of its own, so addFactor($session, 'recovery_code', [])
 * performs a revoking mutation whose failures that branch drops. The first test of
 * the pair below reproduces it with shipped code only.
 *
 * The exclusions above are the other half of this contract and must keep holding.
 * A mutation an observer starts from inside the enrollment stays out, on the paths
 * that wrap the factor call in a transaction and on the one that does not.
 */

/**
 * Substitute $factor for the shipped driver it wraps, in the registry the service
 * resolves from.
 *
 * A fresh FactorRegistry rather than a mutated singleton: registration is
 * write-once by design. The other shipped drivers stay registered because a path
 * resolves more than the factor under test -- changePassword() always asks for
 * 'password', whatever is substituted.
 */
function residualRegistry(Factor $factor): void
{
    $registry = new FactorRegistry();
    $registry->register($factor);

    foreach ([app(PasswordFactor::class), app(TotpFactor::class), app(RecoveryCodeFactor::class)] as $shipped) {
        if ($shipped->id() !== $factor->id()) {
            $registry->register($shipped);
        }
    }

    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn (): FactorRegistry => $registry);
    app()->forgetInstance(CredentialSelfService::class);
}

/** The shipped driver a path enrolls through, for the fixture to wrap. */
function residualInnerFactor(string $path): Factor
{
    return match ($path) {
        'changePassword' => app(PasswordFactor::class),
        'addFactor replacing', 'addFactor adding' => app(TotpFactor::class),
        'regenerateRecoveryCodes' => app(RecoveryCodeFactor::class),
        default => throw new InvalidArgumentException('Unknown enrollment path "' . $path . '".'),
    };
}

/**
 * A credential type for companions that the path's own enrollment cannot touch.
 *
 * Deliberately never the type being enrolled, for two different reasons measured
 * separately.
 *
 * On the NON-REPLACING path it is load-bearing: TotpFactor caps active credentials
 * at 1, EnrollmentGuard checks that as a POST-condition over the whole serialized
 * write, and an additive enrollment disables nothing -- so a companion of the
 * enrolled type is still active when the count is taken and the enrollment is
 * refused for capacity, which reads as "the fix is wrong".
 *
 * On the REPLACING paths capacity does not bite: those drivers open their write
 * with a mass `update(['disabled_at' => ...])` over every active row of the type,
 * companions included, so the count finds them already retired. The separation
 * still matters there, because a companion the driver has already disabled makes
 * the companion mutation's own write a no-op -- the mutation would still run and
 * still withdraw the proof it names, but the fixture would no longer be modelling
 * a factor retiring a credential of its own.
 */
function residualCompanionType(string $path): string
{
    return match ($path) {
        'changePassword', 'regenerateRecoveryCodes' => 'totp',
        'addFactor replacing', 'addFactor adding' => 'recovery_code',
        default => throw new InvalidArgumentException('Unknown enrollment path "' . $path . '".'),
    };
}

/**
 * Whatever the path REPLACES, so its inner mutation is a revoking one and the
 * companions are genuinely not the first.
 *
 * 'addFactor adding' gets nothing on purpose: TotpFactor caps at one active
 * credential, so an existing TOTP row is exactly what makes a non-replacing TOTP
 * enrollment refuse.
 */
function residualPredecessor(string $path): void
{
    match ($path) {
        // residualUser() already enrolled the password this path replaces.
        'changePassword', 'addFactor adding' => null,
        'addFactor replacing' => lateCredential('totp', 'JBSWY3DPEHPK3PXP-existing'),
        'regenerateRecoveryCodes' => app(RecoveryCodeFactor::class)->enroll(1, []),
        default => throw new InvalidArgumentException('Unknown enrollment path "' . $path . '".'),
    };
}

/** Run one enrollment path against whatever residualRegistry() installed. */
function residualEnroll(string $path): SelfServiceResult
{
    // Resolved here rather than by the caller: residualRegistry() and
    // residualIssuer() both forget the service instance, and a service captured
    // before either would carry the shipped registry or the real issuers.
    $service = app(CredentialSelfService::class);
    $session = residualSession();

    return match ($path) {
        'changePassword' => $service->changePassword($session, 'new-password'),
        'addFactor replacing' => $service->addFactor($session, 'totp', ['label' => 'ada@acme.example', 'replace' => true]),
        'addFactor adding' => $service->addFactor($session, 'totp', ['label' => 'ada@acme.example']),
        'regenerateRecoveryCodes' => $service->regenerateRecoveryCodes($session),
        default => throw new InvalidArgumentException('Unknown enrollment path "' . $path . '".'),
    };
}

/**
 * A CompanionRetiringFactor for $path whose companions each strand a proof.
 *
 * Each proof is created immediately before the mutation that withdraws it, so both
 * are later than the service's own revocation pass and neither could have been
 * caught by it. That is what makes the second companion the only possible source
 * of the second identity.
 *
 * @param  list<array{0: int, 1: string}>  $companions  credential id, token key
 */
function residualRetiringFactor(string $path, array $companions, bool $throwsAfterCompanions = false, ?Closure $afterCompanions = null): CompanionRetiringFactor
{
    $type = residualCompanionType($path);
    $retiring = [];

    foreach ($companions as [$credentialId, $tokenKey]) {
        $retiring[] = ['id' => $credentialId, 'before' => function () use ($tokenKey, $type, $credentialId): void {
            residualToken($tokenKey, $type, $credentialId);
        }];
    }

    return new CompanionRetiringFactor(residualInnerFactor($path), $retiring, $throwsAfterCompanions, $afterCompanions);
}

/* ---- shape one: every mutation an enrollment performs must report ------ */

it('reports failures from every mutation an enrollment performs, not only the first', function (string $path): void {
    residualUser();
    residualPredecessor($path);

    $type = residualCompanionType($path);
    $first = lateCredential($type, 'companion-first');
    $second = lateCredential($type, 'companion-second');

    $issuer = residualIssuer(['late-first', 'late-second']);

    $factor = residualRetiringFactor($path, [[$first->id, 'late-first'], [$second->id, 'late-second']]);
    residualRegistry($factor);

    $result = residualEnroll($path);

    /*
     * Premises first, each on its own expectation. The defect's signature is an
     * EMPTY list rather than a short one -- the inner driver's own mutation is the
     * first, claims the single report EnrollmentResult can carry, and excludes every
     * companion -- and an empty list reads identically to "no revocation was
     * attempted". A chain that chases the conclusion first cannot tell them apart.
     */
    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($factor->enrollCalls)->toBe(1);
    // Entered, in order. Recorded before each revoking() call, so completion is
    // what the disabled_at assertions below establish rather than this one.
    expect($factor->mutated)->toBe([$first->id, $second->id], 'both companion mutations should have been entered, in order');
    /*
     * ATTEMPTED, not revoked: both are configured to fail, so neither can appear
     * among the successes. No message argument on toContain -- it is VARIADIC, so a
     * second argument becomes another value the array must contain.
     */
    expect($issuer->attempted)->toContain('late-first');
    expect($issuer->attempted)->toContain('late-second');

    // The writes were never the defect, and a fix that broke them would be worse.
    expect(AuthCredential::query()->whereKey($first->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect(AuthCredential::query()->whereKey($second->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect(DB::table('auth_token_assurances')->where('token_key', 'late-first')->exists())->toBeFalse();
    expect(DB::table('auth_token_assurances')->where('token_key', 'late-second')->exists())->toBeFalse();

    // And only then the claim: BOTH identities reach the caller.
    expect(residualPairs($result->driverFailures))
        ->toBe([['sanctum', 'late-first'], ['sanctum', 'late-second']]);
})->with([
    'changePassword',
    'addFactor replacing',
    'addFactor adding',
    'regenerateRecoveryCodes',
]);

it('reports an enrollment\'s second mutation when only the second fails', function (): void {
    residualUser();

    $type = residualCompanionType('changePassword');
    $first = lateCredential($type, 'companion-first');
    $second = lateCredential($type, 'companion-second');

    /*
     * Only the second companion's revocation fails. This is the case that separates
     * a real fix from one that merely returns the FIRST mutation's report under a
     * new name: here the first has nothing to report, so an implementation still
     * bound to it hands back an empty list and calls the cleanup clean while a token
     * is live at its issuer.
     */
    $issuer = residualIssuer(['late-second']);

    $factor = residualRetiringFactor('changePassword', [[$first->id, 'late-first'], [$second->id, 'late-second']]);
    residualRegistry($factor);

    $result = residualEnroll('changePassword');

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($factor->mutated)->toBe([$first->id, $second->id], 'both companion mutations should have run');

    // The first token really was revoked, so its absence from the list below is a
    // success rather than a second thing going unreported.
    expect($issuer->revoked)->toContain('late-first');
    expect(DB::table('auth_token_assurances')->where('token_key', 'late-first')->exists())->toBeFalse();

    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'late-second']]);
});

it('keeps a driver diagnostic out of what a multi-mutation enrollment hands back', function (string $path): void {
    residualUser();
    residualPredecessor($path);

    $companion = lateCredential(residualCompanionType($path), 'companion-only');

    residualIssuer(['late-companion']);

    $factor = residualRetiringFactor($path, [[$companion->id, 'late-companion']]);
    residualRegistry($factor);

    $result = residualEnroll($path);

    /*
     * Premises first, as everywhere else in this file. Without them a capacity
     * refusal on the additive path -- the fragility residualCompanionType()
     * describes -- arrives as an empty identity list, which reads as "the
     * reporting channel is dead" when the truth is that no enrollment happened.
     */
    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($factor->mutated)->toBe([$companion->id], 'the companion mutation should have run');

    /*
     * Identities only, through every route a caller could read the result by.
     * print_r and json_encode both, because they disagree: json_encode consults
     * JsonSerializable and print_r does not, so a diagnostic hidden from one can
     * still be reachable through the other.
     */
    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'late-companion']])
        ->and(print_r($result->driverFailures, true))->not->toContain(RESIDUAL_SENTINEL)
        ->and(json_encode($result, JSON_THROW_ON_ERROR))->not->toContain(RESIDUAL_SENTINEL)
        ->and(print_r($result, true))->not->toContain(RESIDUAL_SENTINEL);
})->with([
    // Every entry point. The structural split that matters is through
    // mutateCredentials() versus returning before it, but no dataset depends on a
    // transaction being wrapped around the factor call -- the identity travels the
    // same way either way, which is why all four can share one body.
    'changePassword',
    'addFactor replacing',
    'addFactor adding',
    'regenerateRecoveryCodes',
]);

it('reports every companion and still excludes a nested observer during an enrollment', function (string $path): void {
    residualUser();
    residualPredecessor($path);

    $type = residualCompanionType($path);
    $first = lateCredential($type, 'companion-first');
    $second = lateCredential($type, 'companion-second');
    $unrelated = lateCredential($type, 'companion-other');

    $issuer = residualIssuer(['late-first', 'late-second', 'unrelated']);

    // Assigned by the observer below, which the first assertion proves ran.
    $nested = null;
    $fired = false;

    /*
     * created(), not updating(). An enrollment's own window is the INSERT of the
     * credential it creates, which fires from inside the inner driver's mutation --
     * so this nested mutation begins a level deeper than the enrollment itself, and
     * must stay out of the enrollment's residual. Different event, same
     * contamination: the exclusion must not depend on the delivery.
     */
    AuthCredential::created(function (AuthCredential $credential) use (&$nested, &$fired, $unrelated, $type): void {
        if ($fired || $credential->id === $unrelated->id) {
            return;
        }
        $fired = true;

        residualToken('unrelated', $type, $unrelated->id);

        $nested = app(CredentialMutation::class)->revoking(
            SubjectKey::forConfiguredUser(1),
            [(string) $unrelated->id],
            static fn (): null => null,
        );
    });

    $factor = residualRetiringFactor($path, [[$first->id, 'late-first'], [$second->id, 'late-second']]);
    residualRegistry($factor);

    $result = residualEnroll($path);

    $nestedResult = $nested ?? throw new RuntimeException('The created observer never ran a mutation.');

    expect($fired)->toBeTrue();
    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($factor->mutated)->toBe([$first->id, $second->id], 'both companion mutations should have run');
    expect($issuer->attempted)->toContain('late-first');
    expect($issuer->attempted)->toContain('late-second');
    expect($issuer->attempted)->toContain('unrelated');
    // The observer's own mutation reported its own failure, to the observer.
    expect(internalPairs($nestedResult->driverFailures))->toBe([['sanctum', 'unrelated']]);
    expect(DB::table('auth_token_assurances')->where('token_key', 'unrelated')->exists())->toBeFalse();
    /*
     * And excluding it was not achieved by cancelling it: the nested mutation is
     * inert by construction, so its credential must still be active. Suppressing
     * the observer's work would satisfy the conclusion below while silently
     * dropping a write the host asked for.
     */
    expect(AuthCredential::query()->whereKey($unrelated->id)->whereNull('disabled_at')->exists())->toBeTrue();

    // Both halves at once: every companion named, the observer's token not.
    expect(residualPairs($result->driverFailures))
        ->toBe([['sanctum', 'late-first'], ['sanctum', 'late-second']]);
})->with([
    // Every entry point, because the exclusion is the half a widened collector
    // would break and it should be held on all of them. It holds by mutation
    // nesting depth, which counts CredentialMutation frames only -- transaction
    // independent by construction, so no dataset here depends on a transaction
    // being wrapped around the factor call. The failed-enrollment test at the end
    // of this file is the one test that does, and it names that dependency itself.
    'changePassword',
    'addFactor replacing',
    'addFactor adding',
    'regenerateRecoveryCodes',
]);

it('reports what the driver itself recorded alongside what the caller collected', function (): void {
    residualUser();

    $companion = lateCredential(residualCompanionType('changePassword'), 'companion-only');

    $issuer = residualIssuer(['late-companion']);

    /*
     * Two channels, and both must be read.
     *
     * 'late-companion' can only be learned on the CALLER's side: it is a failure
     * from the factor's second mutation, which the factor cannot put in the result
     * it returns. 'driver-side' can only be learned from the DRIVER's report: it
     * stands for a revocation the factor performed at its own issuer, outside
     * CredentialMutation, so no scope the service opens can observe it.
     *
     * Nothing else in this suite separates a caller that MERGES the driver's report
     * from one that replaces it with its own -- measured: an implementation that
     * ignores EnrollmentResult::$driverFailures entirely passes every other test in
     * the package. That would silently retire a public channel, since both
     * EnrollmentResult's report argument and CredentialDriverFailureReport::record()
     * are API a host driver is meant to use.
     */
    $retiring = residualRetiringFactor('changePassword', [[$companion->id, 'late-companion']]);
    $factor = new SelfReportingFactor($retiring, [['sanctum', 'driver-side']]);
    residualRegistry($factor);

    $result = residualEnroll('changePassword');

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($retiring->mutated)->toBe([$companion->id], 'the companion mutation should have run');
    expect($issuer->attempted)->toContain('late-companion');
    expect(DB::table('auth_token_assurances')->where('token_key', 'late-companion')->exists())->toBeFalse();

    // Both, de-duplicated and sorted. Either one alone is a channel gone silent.
    expect(residualPairs($result->driverFailures))
        ->toBe([['sanctum', 'driver-side'], ['sanctum', 'late-companion']]);
});

/* ---- shape two: the non-replacing addFactor branch reported nothing --- */

it('reports a driver failure from an enrollment that replaced nothing', function (): void {
    residualUser();

    /*
     * Shipped code throughout -- no substituted factor, no interception.
     * RecoveryCodeFactor::enroll() disables the existing active set whether or not
     * the caller asked to replace, so this reaches addFactor()'s NON-replacing
     * branch and still performs a revoking mutation. That branch returns before
     * mutateCredentials() and built its result from the secrets alone, so the
     * failure had nowhere to go.
     *
     * No interception is needed to strand the proof either: the non-replacing branch
     * runs no revocation pass of its own, so a proof seeded here is still standing
     * when the factor's own mutation withdraws it.
     */
    $existing = app(RecoveryCodeFactor::class)->enroll(1, [])->credentials[0];
    residualToken('late', 'recovery_code', $existing->id);

    $issuer = residualIssuer();

    $result = app(CredentialSelfService::class)->addFactor(residualSession(), 'recovery_code', []);

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    // A new set really was minted, so this is a completed enrollment rather than a
    // path that returned early for some other reason.
    expect($result->secrets)->not->toBe([]);
    expect(AuthCredential::query()->whereKey($existing->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect($issuer->attempted)->toContain('late');
    expect(DB::table('auth_token_assurances')->where('token_key', 'late')->exists())->toBeFalse();

    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'late']]);
    expect(print_r($result, true))->not->toContain(RESIDUAL_SENTINEL);
});

it('reports nothing from an enrollment whose driver revocations all succeeded', function (): void {
    residualUser();

    $existing = app(RecoveryCodeFactor::class)->enroll(1, [])->credentials[0];
    residualToken('late', 'recovery_code', $existing->id);

    /*
     * The positive control for the test above. Identical setup with an issuer that
     * fails nothing: an implementation that reported this branch's failures by
     * reporting something unconditionally would pass that test and fail this one.
     *
     * The premise is asserted, not assumed. `revoked` proves the revocation was
     * genuinely attempted and genuinely succeeded, so the empty list below means
     * "nothing to report" rather than "the channel is dead".
     */
    $issuer = residualIssuer([]);

    $result = app(CredentialSelfService::class)->addFactor(residualSession(), 'recovery_code', []);

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($issuer->revoked)->toContain('late');
    expect(DB::table('auth_token_assurances')->where('token_key', 'late')->exists())->toBeFalse();

    expect($result->driverFailures)->toBe([]);
});

/*
 * RETIRED by #79, which is what this test said should happen to it.
 *
 * It asserted that a mutation the factor completed before failing had its driver
 * failure reported, and it depended on addFactor()'s non-replacing branch wrapping
 * the factor call in no transaction -- which is exactly the defect #79 names. With
 * that transaction in place the mutation rolls back, afterCommit never runs, no
 * token is stranded at any issuer, and the scenario is unreachable rather than
 * wrong. Measured: adding the transaction left every other case in this file green
 * and failed this one at a PREMISE, its issuer never having been asked.
 *
 * So the reporting it checked is not lost, it is moot: after a DRIVER THROW there is
 * nothing to report. CredentialSelfServiceTest holds that replacement contract.
 *
 * Deliberately narrow wording, because the broader claim would be false: a failure
 * in an afterCommit LISTENER still leaves the credential committed, since callbacks
 * run after the commit and past the point any transaction can undo. The additive
 * branch still reports on that path, and the case immediately below keeps it
 * honest. What that branch's OUTCOME should say when it failed over committed state
 * is #84, and nothing here pre-empts it.
 *
 * The other post-commit test further down this file exercises changePassword, a
 * different branch, so it is not cover for this one.
 */

it('reports an additive enrollment\'s committed failure when a post-commit listener threw', function (): void {
    residualUser();

    $companion = lateCredential(residualCompanionType('addFactor adding'), 'companion-only');

    $issuer = residualIssuer(['late-companion']);

    /*
     * The one guard on the additive branch's FAILURE-path reporting, and it needs to
     * exist independently of #79.
     *
     * The edit it exists to catch is not a contrived one. Once that branch wraps the
     * factor call in a transaction, its inner try/catch reads as redundant, and
     * hoisting it outside collect() is the obvious tidy-up -- which silently loses
     * the report on every failure path while leaving the success path untouched.
     * Measured: that hoist fails this case and nothing else in tests/Database, all
     * 1076 of them. It is the executable form of a warning the retired test carried
     * only in prose -- collect() RETHROWS, so a scope the exception escapes never
     * returns its report at all.
     *
     * An afterCommit listener rather than a driver throw, because that is the shape
     * #79's rollback cannot reach: the commit happens first and the callbacks after,
     * so by the time this one throws the issuer has already been asked and failed.
     *
     * Two things deliberately NOT asserted. The OUTCOME, because whether a refusal is
     * the right thing to say over committed state is #84's question and pinning it
     * here would decide it by accident. And the credential's durability, which the
     * paragraph above describes but nothing below checks: #84 may resolve this by
     * RECONCILING -- a best-effort undo plus a residual report -- rather than by
     * renaming the outcome, and a durability pin would have to move if it did.
     * Committedness is still established transitively, because the proof withdrawal
     * asserted below happens in the same transaction as the companion's disable, so
     * an absent assurance row can only mean that transaction committed.
     *
     * What is asserted is that the identity still travels, whatever the outcome ends
     * up being called.
     */
    $factor = residualRetiringFactor(
        'addFactor adding',
        [[$companion->id, 'late-companion']],
        afterCompanions: static function (): void {
            DB::connection()->afterCommit(static function (): void {
                throw new RuntimeException('A post-commit listener failed after the credential write committed.');
            });
        },
    );
    residualRegistry($factor);

    $result = residualEnroll('addFactor adding');

    // Premises: the mutation ran, its revocation was attempted, and it failed.
    expect($factor->mutated)->toBe([$companion->id], 'the companion mutation should have run');
    expect($issuer->attempted)->toContain('late-companion');
    expect(DB::table('auth_token_assurances')->where('token_key', 'late-companion')->exists())->toBeFalse();

    // The conclusion: the identity reaches the caller, and carries no diagnostic.
    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'late-companion']]);
    expect(print_r($result, true))->not->toContain(RESIDUAL_SENTINEL);
});

it('reports a committed mutation\'s driver failure when a post-commit listener then failed', function (): void {
    residualUser();

    $companion = lateCredential(residualCompanionType('changePassword'), 'companion-only');

    $issuer = residualIssuer(['late-companion']);

    /*
     * The third way a failure strands, and the one that survives a transaction.
     *
     * Connection::commit() commits the PDO transaction FIRST and only then runs its
     * afterCommit callbacks, so a callback that throws propagates out of
     * transaction() into mutateCredentials()'s catch with the write already durable
     * and the driver revocations -- registered earlier, so run earlier -- already
     * attempted. The operation reports CredentialChangeFailed over committed state.
     *
     * Vouch's own per-token callbacks cannot reach here: both the issuer revoke and
     * the log line are individually wrapped. A HOST's can, and ordinarily does --
     * Laravel dispatches queued jobs afterCommit by default, so any listener on a
     * credential event is a candidate.
     *
     * Registered after the companion mutations rather than before, because
     * afterCommit callbacks run in registration order: registered first, this would
     * run ahead of the revocation callbacks and there would be no failure to report.
     */
    $factor = residualRetiringFactor('changePassword', [[$companion->id, 'late-companion']], afterCompanions: static function (): void {
        DB::connection()->afterCommit(static function (): void {
            throw new RuntimeException('A post-commit listener failed after the credential write committed.');
        });
    });
    residualRegistry($factor);

    $result = residualEnroll('changePassword');

    /*
     * Premises first, and here they carry most of the test's weight: the whole point
     * is that a FAILED outcome sits on top of work that really happened, so each
     * piece of that work is asserted before the reporting claim.
     */
    expect($result->outcome)->toBe(SelfServiceOutcome::CredentialChangeFailed);
    expect($factor->mutated)->toBe([$companion->id], 'the companion mutation should have run');
    expect($issuer->attempted)->toContain('late-companion');
    // Durable despite the failure: commit preceded the callback that threw.
    expect(AuthCredential::query()->whereKey($companion->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect(DB::table('auth_token_assurances')->where('token_key', 'late-companion')->exists())->toBeFalse();

    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'late-companion']]);
    expect(print_r($result, true))->not->toContain(RESIDUAL_SENTINEL);
});

/* ---- shape four: depth has unwound by the time deferred work runs ------ */

/**
 * An issuer that fails for each of $failing, and runs a hook when asked to revoke
 * the token that keys it.
 *
 * Each hook fires at most ONCE, because the mutation a hook starts revokes tokens of
 * its own and re-entering would recurse. Keyed on the token as well, so a hook cannot
 * run from some other revocation and leave the test asserting about the wrong window.
 *
 * More than one hook because the contract is recursive: a collection opened inside a
 * deferred callback has the same claim on its own mutations, and excluding a mutation
 * one level down needs a second deferred callback to start it.
 *
 * @param  list<string>  $failing
 * @param  array<string, Closure>  $hooks  token key => what to run while revoking it
 */
function residualDeferredIssuer(array $failing, array $hooks, DeferredIssuerProbe $probe): RecordingIssuer
{
    $ran = [];
    $issuer = new RecordingIssuer('sanctum');
    $issuer->onRevoke = function () use (&$issuer, &$ran, $failing, $hooks, $probe): null {
        $tokenKey = end($issuer->attempted);

        if (isset($hooks[$tokenKey]) && ! isset($ran[$tokenKey])) {
            $ran[$tokenKey] = true;
            $probe->fired = true;

            /*
             * Zero here is the whole point of the shape. Driver revocation is
             * registered with afterCommit, so for a mutation nested inside the
             * service's transaction it runs at the OUTER commit -- by which time
             * the transaction is closed and the collector's mutation depth has
             * unwound to the caller's. An observer's nested mutation, which the
             * frozen exclusions cover, sees a level of 1 or more instead.
             */
            $probe->transactionLevel = DB::transactionLevel();

            /*
             * Snapshotted here, not read at the end of the test. The flag is set by a
             * factor hook that runs after the originating mutation returns, so by the
             * time a test body reads it it is true whatever the ordering was --
             * measured, that is exactly how a premise asserting the field itself
             * passed under a counter-implementation it was written to reject.
             */
            $probe->returnedWhenCallbackRan = $probe->originatingMutationReturned;

            ($hooks[$tokenKey])();
        }

        if (in_array($tokenKey, $failing, true)) {
            throw new RuntimeException(RESIDUAL_SENTINEL);
        }

        return null;
    };

    app()->instance(TokenIssuerRegistry::class, new TokenIssuerRegistry([$issuer]));
    app()->forgetInstance(CredentialSelfService::class);

    return $issuer;
}

it('keeps a mutation started from a deferred issuer callback out of the enrollment residual', function (string $path): void {
    residualUser();
    residualUser(2);
    residualPredecessor($path);

    $type = residualCompanionType($path);
    $companion = lateCredential($type, 'companion-one');
    $foreign = lateCredential($type, 'foreign-credential', 2);

    /*
     * ANOTHER SUBJECT's token, which is what raises this above a reporting
     * nicety: the identifier reaches a result the caller may render or log, and
     * the caller is told to reconcile a token belonging to someone else.
     */
    residualToken('foreign-user-token', $type, $foreign->id, 2);

    $probe = new DeferredIssuerProbe;

    $issuer = residualDeferredIssuer(
        ['companion-token', 'foreign-user-token'],
        ['companion-token' => function () use ($probe, $foreign): void {
            /*
             * A real write, not a null one: the point of the shape is an independent
             * mutation doing its own work for its own subject, and a null write
             * withdraws the proof while leaving the credential enabled -- which
             * would make the premise below unassertable.
             */
            $probe->nested = app(CredentialMutation::class)->revoking(
                SubjectKey::forConfiguredUser(2),
                [(string) $foreign->id],
                static function () use ($foreign): null {
                    AuthCredential::query()->whereKey($foreign->id)->firstOrFail()
                        ->update(['disabled_at' => now()]);

                    return null;
                },
            );
        }],
        $probe,
    );

    $factor = residualRetiringFactor(
        $path,
        [[$companion->id, 'companion-token']],
        afterCompanions: static function () use ($probe): void {
            $probe->originatingMutationReturned = true;
        },
    );
    residualRegistry($factor);

    $result = residualEnroll($path);

    /*
     * Premises first, each on its own expectation, because every way this test can
     * be wrong looks like success from the conclusion alone. An empty caller list
     * would pass a conclusion-first chain whether the exclusion worked or the
     * enrollment never revoked anything at all.
     */
    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($factor->enrollCalls)->toBe(1);
    expect($probe->fired)->toBeTrue();

    /*
     * The window, in two parts, because the first part alone does not establish it.
     * Level zero rules out a transactional observer. What rules out "still inside
     * during()" is that the companion mutation had already RETURNED when the
     * callback ran -- measured, with the service's transaction wrappers removed the
     * callback fires inside a top-level mutation's open during() and the level is
     * zero there too, so a test resting on the level alone passes in a shape it
     * does not describe.
     */
    expect($probe->transactionLevel)->toBe(0);
    expect($probe->returnedWhenCallbackRan)->toBeTrue();

    // Both revocations were ATTEMPTED and both were configured to fail, so neither
    // can appear among the successes. toContain is variadic; no message argument.
    expect($issuer->attempted)->toContain('companion-token');
    expect($issuer->attempted)->toContain('foreign-user-token');

    // The foreign mutation did its own work and kept its own failure.
    $nested = $probe->nested ?? throw new RuntimeException('The deferred callback started no mutation.');
    expect(internalPairs($nested->driverFailures))->toBe([['sanctum', 'foreign-user-token']]);
    expect(DB::table('auth_token_assurances')->where('token_key', 'foreign-user-token')->exists())->toBeFalse();
    expect(AuthCredential::query()->whereKey($foreign->id)->whereNull('disabled_at')->exists())->toBeFalse();

    // And the enrollment's own work happened, so its inclusion below is a report
    // rather than an absence.
    expect(AuthCredential::query()->whereKey($companion->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect(DB::table('auth_token_assurances')->where('token_key', 'companion-token')->exists())->toBeFalse();

    /*
     * The claim, both halves at once. The companion is the caller's own work and
     * must be named; the foreign token is not and must not be. Asserting the whole
     * list rather than an absence is what makes over-correction visible -- a fix
     * that silenced deferred reporting outright would empty this.
     */
    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'companion-token']]);

    /*
     * And nowhere else on the result either. The identity assertion above reads one
     * list; a host renders or logs the whole object, so the foreign key must not be
     * reachable through any other property. json_encode and print_r disagree about
     * what they walk, so both.
     */
    expect(print_r($result, true))->not->toContain('foreign-user-token');
    expect(json_encode($result, JSON_THROW_ON_ERROR))->not->toContain('foreign-user-token');
})->with([
    'changePassword',
    'addFactor replacing',
    'addFactor adding',
    'regenerateRecoveryCodes',
]);

it('keeps a mutation started from a deferred issuer callback out of a removal residual', function (): void {
    residualUser();
    residualUser(2);

    $target = lateCredential('totp', 'JBSWY3DPEHPK3PXP');
    $foreign = lateCredential('totp', 'foreign-credential', 2);

    residualToken('foreign-user-token', 'totp', $foreign->id, 2);

    $probe = new DeferredIssuerProbe;

    $issuer = residualDeferredIssuer(
        ['target-late', 'foreign-user-token'],
        ['target-late' => function () use ($probe, $foreign): void {
            /*
             * A real write, not a null one: the point of the shape is an independent
             * mutation doing its own work for its own subject, and a null write
             * withdraws the proof while leaving the credential enabled -- which
             * would make the premise below unassertable.
             */
            $probe->nested = app(CredentialMutation::class)->revoking(
                SubjectKey::forConfiguredUser(2),
                [(string) $foreign->id],
                static function () use ($foreign): null {
                    AuthCredential::query()->whereKey($foreign->id)->firstOrFail()
                        ->update(['disabled_at' => now()]);

                    return null;
                },
            );
        }],
        $probe,
    );

    /*
     * The removal path, because mutateCredentials() has the same shape the
     * enrollment branch acquired: collect() OUTSIDE the transaction that wraps the
     * factor call, so the factor's mutation is nested and its driver work defers to
     * a commit that happens inside the collection but after during() has returned.
     * A fix confined to the additive enrollment branch leaves this live.
     */
    $factor = new InterceptingFactor(
        app(TotpFactor::class),
        beforeRevoke: function () use ($target): null {
            residualToken('target-late', $target->type, $target->id);

            return null;
        },
        afterRevoke: static function () use ($probe): void {
            $probe->originatingMutationReturned = true;
        },
    );
    residualRegistry($factor);

    $result = app(CredentialSelfService::class)->removeFactor(residualSession(), $target->id);

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($probe->fired)->toBeTrue();
    expect($probe->transactionLevel)->toBe(0);
    expect($probe->returnedWhenCallbackRan)->toBeTrue();
    expect($issuer->attempted)->toContain('target-late');
    expect($issuer->attempted)->toContain('foreign-user-token');

    $nested = $probe->nested ?? throw new RuntimeException('The deferred callback started no mutation.');
    expect(internalPairs($nested->driverFailures))->toBe([['sanctum', 'foreign-user-token']]);
    expect(DB::table('auth_token_assurances')->where('token_key', 'foreign-user-token')->exists())->toBeFalse();
    expect(AuthCredential::query()->whereKey($foreign->id)->whereNull('disabled_at')->exists())->toBeFalse();

    expect(AuthCredential::query()->whereKey($target->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect(DB::table('auth_token_assurances')->where('token_key', 'target-late')->exists())->toBeFalse();

    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'target-late']]);
    expect(print_r($result, true))->not->toContain('foreign-user-token');
    expect(json_encode($result, JSON_THROW_ON_ERROR))->not->toContain('foreign-user-token');
});

it('keeps a deferred callback\'s mutation out of the residual when it is the same subject', function (): void {
    residualUser();

    $companion = lateCredential('recovery_code', 'companion-one');
    $sibling = lateCredential('recovery_code', 'sibling-credential');

    /*
     * ONE subject, and that is the point. The filed defect reached a token belonging
     * to somebody else, which is the worst consequence but not the mechanism: the
     * collector discriminates on mutation DEPTH, and the reason it does is recorded
     * in its own docblock -- adding the subject does not help, because both
     * operations can belong to one user.
     *
     * So a fix that excluded foreign work by comparing subjects would turn every
     * other test in this shape green while leaving this one failing, and would leave
     * the caller reporting a token its own enrollment never touched. Measured
     * against the unfixed class, this contaminates exactly as the cross-subject
     * cases do.
     */
    residualToken('sibling-token', 'recovery_code', $sibling->id);

    $probe = new DeferredIssuerProbe;

    $issuer = residualDeferredIssuer(
        ['companion-token', 'sibling-token'],
        ['companion-token' => function () use ($probe, $sibling): void {
            $probe->nested = app(CredentialMutation::class)->revoking(
                SubjectKey::forConfiguredUser(1),
                [(string) $sibling->id],
                static function () use ($sibling): null {
                    AuthCredential::query()->whereKey($sibling->id)->firstOrFail()
                        ->update(['disabled_at' => now()]);

                    return null;
                },
            );
        }],
        $probe,
    );

    $factor = residualRetiringFactor(
        'addFactor adding',
        [[$companion->id, 'companion-token']],
        afterCompanions: static function () use ($probe): void {
            $probe->originatingMutationReturned = true;
        },
    );
    residualRegistry($factor);

    $result = residualEnroll('addFactor adding');

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($probe->fired)->toBeTrue();
    expect($probe->transactionLevel)->toBe(0);
    expect($probe->returnedWhenCallbackRan)->toBeTrue();
    expect($issuer->attempted)->toContain('companion-token');
    expect($issuer->attempted)->toContain('sibling-token');

    $nested = $probe->nested ?? throw new RuntimeException('The deferred callback started no mutation.');
    expect(internalPairs($nested->driverFailures))->toBe([['sanctum', 'sibling-token']]);
    expect(AuthCredential::query()->whereKey($sibling->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect(DB::table('auth_token_assurances')->where('token_key', 'sibling-token')->exists())->toBeFalse();

    expect(AuthCredential::query()->whereKey($companion->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect(DB::table('auth_token_assurances')->where('token_key', 'companion-token')->exists())->toBeFalse();

    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'companion-token']]);
    expect(print_r($result, true))->not->toContain('sibling-token');
});

it('keeps a deferred callback\'s mutation out of the residual when the callback opens its own transaction', function (): void {
    residualUser();
    residualUser(2);

    $companion = lateCredential('recovery_code', 'companion-one');
    $foreign = lateCredential('recovery_code', 'foreign-credential', 2);
    residualToken('foreign-user-token', 'recovery_code', $foreign->id, 2);

    $probe = new DeferredIssuerProbe;

    /*
     * Opening a transaction inside an issuer callback does not make its mutations
     * part of the enrollment.
     *
     * The callback owns a transaction of its own, and this case exists because the
     * cheapest wrong fix passes every other test in this shape. Measured: a guard in
     * reportsFor() returning no scopes while `transactionLevel() === 0` turned the
     * whole file green -- 38 passed -- because a deferred callback ordinarily runs
     * with no transaction open. It is the depth that has unwound, not the
     * transaction stack, and the two coincide only by habit. Opening a transaction
     * here separates them: the level is 1 while the depth is still the caller's, the
     * contamination is identical, and the guard no longer hides it.
     */
    $issuer = residualDeferredIssuer(
        ['companion-token', 'foreign-user-token'],
        ['companion-token' => function () use ($probe, $foreign): void {
            DB::transaction(function () use ($probe, $foreign): void {
                $probe->nested = app(CredentialMutation::class)->revoking(
                    SubjectKey::forConfiguredUser(2),
                    [(string) $foreign->id],
                    static function () use ($foreign): null {
                        AuthCredential::query()->whereKey($foreign->id)->firstOrFail()
                            ->update(['disabled_at' => now()]);

                        return null;
                    },
                );
            });
        }],
        $probe,
    );

    $factor = residualRetiringFactor(
        'addFactor adding',
        [[$companion->id, 'companion-token']],
        afterCompanions: static function () use ($probe): void {
            $probe->originatingMutationReturned = true;
        },
    );
    residualRegistry($factor);

    $result = residualEnroll('addFactor adding');

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($factor->enrollCalls)->toBe(1);
    expect($probe->fired)->toBeTrue();
    expect($probe->returnedWhenCallbackRan)->toBeTrue();

    // Entered at level zero, as every deferred callback does; the transaction this
    // one opens is inside that, and is what the level-based guard would have read.
    expect($probe->transactionLevel)->toBe(0);

    expect($issuer->attempted)->toContain('companion-token');
    expect($issuer->attempted)->toContain('foreign-user-token');

    $nested = $probe->nested ?? throw new RuntimeException('The deferred callback started no mutation.');
    expect(internalPairs($nested->driverFailures))->toBe([['sanctum', 'foreign-user-token']]);
    expect(AuthCredential::query()->whereKey($foreign->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect(DB::table('auth_token_assurances')->where('token_key', 'foreign-user-token')->exists())->toBeFalse();

    expect(AuthCredential::query()->whereKey($companion->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect(DB::table('auth_token_assurances')->where('token_key', 'companion-token')->exists())->toBeFalse();

    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'companion-token']]);
    expect(print_r($result, true))->not->toContain('foreign-user-token');
    expect(json_encode($result, JSON_THROW_ON_ERROR))->not->toContain('foreign-user-token');
});

it('keeps both of a deferred callback\'s sequential mutations out of the residual', function (bool $firstFails): void {
    residualUser();
    residualUser(2);

    $companion = lateCredential('recovery_code', 'companion-one');
    $first = lateCredential('recovery_code', 'foreign-first', 2);
    $second = lateCredential('recovery_code', 'foreign-second', 2);
    residualToken('foreign-first-token', 'recovery_code', $first->id, 2);
    residualToken('foreign-second-token', 'recovery_code', $second->id, 2);

    $probe = new DeferredIssuerProbe;

    /*
     * TWO mutations in the one callback, sequentially, and this case exists because
     * the single-mutation cases alone accept a guard that cannot hold.
     *
     * Measured: a boolean "inside deferred work" flag -- set around each issuer
     * revocation and cleared in a finally -- turns the whole file green at 39
     * passed. It fails only here, because the FIRST nested mutation's own driver
     * callbacks run and finish inside this one, clearing the flag while this
     * callback is still going, so the second mutation asks with the flag down and
     * lands on the caller's report. Depth does not have that failure mode: the
     * second mutation begins at the same depth the first did, and both are a level
     * below nothing -- which is the point, since neither is the caller's work.
     */
    /*
     * Whether the FIRST revocation fails is a dimension, not a detail. A
     * discriminator that unwinds its context only on the failing path -- in a catch
     * rather than a finally, or the reverse -- is correct on whichever path the test
     * happens to take and leaks on the other. Measured, unwinding only in catch
     * passed all 41 cases while the first revocation always threw; with the first
     * succeeding and the second failing, the collection loses the second identity.
     * Successful cleanup must not hide a later failure from the operation that asked
     * for it.
     */
    $failing = $firstFails
        ? ['companion-token', 'foreign-first-token', 'foreign-second-token']
        : ['companion-token', 'foreign-second-token'];

    $issuer = residualDeferredIssuer(
        $failing,
        ['companion-token' => function () use ($probe, $first, $second): void {
            $revoke = static function (AuthCredential $credential) use ($probe): void {
                $probe->nestedMutations[] = app(CredentialMutation::class)->revoking(
                    SubjectKey::forConfiguredUser(2),
                    [(string) $credential->id],
                    static function () use ($credential): null {
                        AuthCredential::query()->whereKey($credential->id)->firstOrFail()
                            ->update(['disabled_at' => now()]);

                        return null;
                    },
                );
            };

            /*
             * BOTH mutations inside one collection the callback opens, which carries
             * two claims at once.
             *
             * The inclusion half: a collection opened inside deferred work must hear
             * its own mutations. Measured, a flag that suppresses reporting while
             * deferred work runs -- saving and restoring the previous value, so a
             * sequential mutation cannot clear it early -- passes every exclusion case
             * in this file and fails this, because suppression cannot tell "the
             * enclosing caller must not hear this" from "whoever opened a collection
             * around this mutation must".
             *
             * And a LIFETIME claim, which is why both run in here rather than one.
             * The first mutation's issuer throws. Measured, an implementation that
             * tracks callback context correctly but unwinds it outside a `finally`
             * passes all 41 cases when only the second mutation is collected -- the
             * collection captures the already-leaked context and agrees with it. With
             * both inside, the leak costs the second identity and the case fails. A
             * discriminator has to survive the exception, not merely compute the right
             * answer when nothing throws.
             *
             * What is required is the separation, not any one way of expressing it. An
             * earlier version of this comment said raising the nesting depth was the
             * only answer; that overstates it -- a per-connection stack of callback
             * contexts, or suspending only the collections that predate the callback,
             * express the same ownership rule. The assertions do not prefer between
             * them.
             */
            $probe->ownCollection = app(CredentialDriverFailureCollector::class)->collect(
                DB::connection(),
                static function () use ($revoke, $first, $second): null {
                    $revoke($first);
                    $revoke($second);

                    return null;
                },
            );
        }],
        $probe,
    );

    $factor = residualRetiringFactor(
        'addFactor adding',
        [[$companion->id, 'companion-token']],
        afterCompanions: static function () use ($probe): void {
            $probe->originatingMutationReturned = true;
        },
    );
    residualRegistry($factor);

    $result = residualEnroll('addFactor adding');

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($factor->enrollCalls)->toBe(1);
    expect($probe->fired)->toBeTrue();
    expect($probe->transactionLevel)->toBe(0);
    expect($probe->returnedWhenCallbackRan)->toBeTrue();

    // BOTH mutations ran, in order, and each attempted its own revocation.
    expect($probe->nestedMutations)->toHaveCount(2);
    expect($issuer->attempted)->toContain('companion-token');
    expect($issuer->attempted)->toContain('foreign-first-token');
    expect($issuer->attempted)->toContain('foreign-second-token');

    /*
     * Each kept its own failure, which is where these belong -- and when the first
     * revocation was configured to succeed it really did, so the row below is a
     * success rather than a revocation that never happened.
     */
    expect(internalPairs($probe->nestedMutations[0]->driverFailures))
        ->toBe($firstFails ? [['sanctum', 'foreign-first-token']] : []);
    expect(internalPairs($probe->nestedMutations[1]->driverFailures))->toBe([['sanctum', 'foreign-second-token']]);

    if (! $firstFails) {
        expect($issuer->revoked)->toContain('foreign-first-token');
    }

    /*
     * And the collection opened INSIDE the deferred callback hears BOTH of its own
     * mutations. Without the inclusion half the spec accepts suppression, which keeps
     * the caller clean by silencing everyone -- including a caller who asked, in
     * here, for exactly this. Without the SECOND identity it accepts a discriminator
     * that leaks its context when the first issuer throws.
     */
    $own = $probe->ownCollection ?? throw new RuntimeException('The deferred callback opened no collection.');
    expect(residualPairs($own->driverFailures))->toBe($firstFails
        ? [['sanctum', 'foreign-first-token'], ['sanctum', 'foreign-second-token']]
        : [['sanctum', 'foreign-second-token']]);

    expect(AuthCredential::query()->whereKey($first->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect(AuthCredential::query()->whereKey($second->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect(AuthCredential::query()->whereKey($companion->id)->whereNull('disabled_at')->exists())->toBeFalse();

    // And neither reaches the caller, which names only its own companion.
    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'companion-token']]);
    expect(print_r($result, true))->not->toContain('foreign-first-token');
    expect(print_r($result, true))->not->toContain('foreign-second-token');
})->with([
    'first revocation fails' => [true],
    'first revocation succeeds' => [false],
]);

it('keeps a mutation one level further down out of a collection opened inside deferred work', function (): void {
    residualUser();
    residualUser(2);

    $companion = lateCredential('recovery_code', 'companion-one');
    $inner = lateCredential('recovery_code', 'inner-credential', 2);
    $deep = lateCredential('recovery_code', 'deep-credential', 2);
    residualToken('inner-token', 'recovery_code', $inner->id, 2);
    residualToken('deep-token', 'recovery_code', $deep->id, 2);

    $probe = new DeferredIssuerProbe;

    $revoke = static function (AuthCredential $credential, DeferredIssuerProbe $probe): void {
        $probe->nestedMutations[] = app(CredentialMutation::class)->revoking(
            SubjectKey::forConfiguredUser(2),
            [(string) $credential->id],
            static function () use ($credential): null {
                AuthCredential::query()->whereKey($credential->id)->firstOrFail()
                    ->update(['disabled_at' => now()]);

                return null;
            },
        );
    };

    /*
     * The contract one level down, which is the same contract. A collection opened
     * inside a deferred callback owns the mutations the callback itself starts -- and
     * owns them no more than the enclosing caller owned the ones IT did not start.
     *
     * Measured: a flag bound into each collection, so that a collection and a
     * mutation must agree about being inside deferred work, passes all forty cases
     * above. It fails here, because both of these callbacks are inside deferred work
     * and agreeing about that does not distinguish them. The inner collection's own
     * mutation defers an issuer callback of its own; the mutation THAT starts is a
     * level below the inner collection and must stay out of it.
     */
    $issuer = residualDeferredIssuer(
        ['companion-token', 'inner-token', 'deep-token'],
        [
            'companion-token' => function () use ($probe, $inner, $revoke): void {
                $probe->ownCollection = app(CredentialDriverFailureCollector::class)->collect(
                    DB::connection(),
                    static function () use ($probe, $inner, $revoke): null {
                        /*
                         * A transaction opened INSIDE the collection, so the mutation
                         * within it is nested: its driver callbacks defer to this
                         * commit, which lands inside the collection but after the
                         * mutation's own during() returned. That is the state the
                         * whole file is about, reproduced one level down.
                         */
                        DB::transaction(static function () use ($probe, $inner, $revoke): void {
                            $revoke($inner, $probe);
                        });

                        return null;
                    },
                );
            },
            'inner-token' => function () use ($probe, $deep, $revoke): void {
                $revoke($deep, $probe);
            },
        ],
        $probe,
    );

    $factor = residualRetiringFactor(
        'addFactor adding',
        [[$companion->id, 'companion-token']],
        afterCompanions: static function () use ($probe): void {
            $probe->originatingMutationReturned = true;
        },
    );
    residualRegistry($factor);

    $result = residualEnroll('addFactor adding');

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);
    expect($probe->fired)->toBeTrue();
    expect($probe->returnedWhenCallbackRan)->toBeTrue();

    // All three revocations were attempted, so nothing below is an absence.
    expect($issuer->attempted)->toContain('companion-token');
    expect($issuer->attempted)->toContain('inner-token');
    expect($issuer->attempted)->toContain('deep-token');

    // Two mutations ran inside the callbacks, each keeping its own failure.
    expect($probe->nestedMutations)->toHaveCount(2);
    expect(internalPairs($probe->nestedMutations[0]->driverFailures))->toBe([['sanctum', 'inner-token']]);
    expect(internalPairs($probe->nestedMutations[1]->driverFailures))->toBe([['sanctum', 'deep-token']]);

    expect(AuthCredential::query()->whereKey($inner->id)->whereNull('disabled_at')->exists())->toBeFalse();
    expect(AuthCredential::query()->whereKey($deep->id)->whereNull('disabled_at')->exists())->toBeFalse();

    /*
     * Both claims. The inner collection hears its own mutation and not the one a
     * level below it; the enclosing caller hears neither, and names only its own
     * companion.
     */
    $own = $probe->ownCollection ?? throw new RuntimeException('The deferred callback opened no collection.');
    expect(residualPairs($own->driverFailures))->toBe([['sanctum', 'inner-token']]);

    expect(residualPairs($result->driverFailures))->toBe([['sanctum', 'companion-token']]);
    expect(print_r($result, true))->not->toContain('inner-token');
    expect(print_r($result, true))->not->toContain('deep-token');
});
