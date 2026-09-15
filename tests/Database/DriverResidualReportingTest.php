<?php

declare(strict_types=1);

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

    expect($fired)->toBeTrue()
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        // Each operation reports its own, and only its own.
        ->and(residualPairs($result->driverFailures))->toBe([['sanctum', 'target-late']])
        ->and($nested)->not->toBeNull()
        ->and(internalPairs($nested?->driverFailures ?? []))->toBe([['sanctum', 'unrelated']])
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
    'different subject' => 2,
    'same subject, different credential' => 1,
]);
