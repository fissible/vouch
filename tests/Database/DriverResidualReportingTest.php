<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Credentials\CredentialDriverFailure;
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
use Fissible\Vouch\Tests\Support\CompanionRevokingFactor;
use Fissible\Vouch\Tests\Support\InterceptingFactor;
use Fissible\Vouch\Tests\Support\InterceptingPasswordFactor;
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
 * Deliberately never the type being enrolled. PasswordFactor and TotpFactor cap
 * active credentials at 1 and EnrollmentGuard checks that as a POST-condition over
 * the whole serialized write -- so a companion of the enrolled type is still active
 * when the count is taken, and the enrollment is refused for capacity before any of
 * this file's reporting is reachable. That refusal reads as "the fix is wrong".
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
function residualRetiringFactor(string $path, array $companions): CompanionRetiringFactor
{
    $type = residualCompanionType($path);
    $retiring = [];

    foreach ($companions as [$credentialId, $tokenKey]) {
        $retiring[] = ['id' => $credentialId, 'before' => function () use ($tokenKey, $type, $credentialId): void {
            residualToken($tokenKey, $type, $credentialId);
        }];
    }

    return new CompanionRetiringFactor(residualInnerFactor($path), $retiring);
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
    // One path that wraps the factor call in a transaction and one that does not.
    'changePassword',
    'addFactor adding',
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
    // With and without a transaction around the factor call: the discriminator is
    // deliberately not transaction level, and the non-replacing path is the one
    // where a transaction-level discriminator would behave differently.
    'changePassword',
    'addFactor adding',
]);

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
