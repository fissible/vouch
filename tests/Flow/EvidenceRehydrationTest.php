<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\Authenticated;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Support\SystemClock;
use Illuminate\Foundation\Testing\RefreshDatabase;
use OTPHP\TOTP;

uses(RefreshDatabase::class);

/*
 * existingFactors() -- the rehydration of evidence already gathered on an
 * attempt -- had NO test coverage at all. Not weak assertions: no test reached
 * the code.
 *
 * The reason is structural, and worth stating because it will recur. Every flow
 * test in the suite used a single-factor policy, and a single-factor login
 * authenticates on the first satisfied factor without ever re-reading what it
 * stored. Rehydration only happens on the SECOND step of a multi-factor policy,
 * so the whole path -- including every guard deciding whether stored evidence is
 * trustworthy -- was reachable only by a test nobody had written.
 *
 * That makes this the most consequential gap found in the audit so far. Multi-
 * factor policy is the package's reason to exist, and the code that carries
 * evidence between its steps had never run.
 */

function rehydrationBinding(): string
{
    return SessionBinding::for('rehydration-session', BindingDomain::Attempt);
}

function rehydrationFlow(): AuthFlow
{
    return app(AuthFlow::class);
}

/** A password+TOTP policy, both credentials enrolled, identifier verified. */
function rehydrationFixture(): string
{
    AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['password', 'totp']], 'posture' => 'friendly',
    ]);
    AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
    app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example']);

    $begun = rehydrationFlow()->advance(new FlowRequest(null, 'begin', [], rehydrationBinding()));
    assert($begun instanceof Continuing && is_string($begun->handle));

    rehydrationFlow()->advance(
        new FlowRequest($begun->handle, 'submit', ['identifier' => 'ada@acme.example'], rehydrationBinding()),
    );

    return $begun->handle;
}

function rehydrationTotpCode(): string
{
    $secret = AuthCredential::where('user_id', 7)->where('type', 'totp')->firstOrFail()->secret;
    $timestamp = (new SystemClock())->now()->getTimestamp();

    if (! is_string($secret) || $secret === '' || $timestamp < 0) {
        throw new RuntimeException('No usable TOTP secret in the fixture.');
    }

    $totp = TOTP::createFromSecret($secret, new SystemClock());
    $totp->setPeriod(30);
    $totp->setDigits(6);

    return $totp->at($timestamp);
}

it('carries first-factor evidence across a step and completes a two-factor login', function (): void {
    /*
     * The round trip that nothing exercised: encode() writes the password
     * evidence, existingFactors() reads it back on the next step, and the kernel
     * evaluates BOTH factors together.
     *
     * The amr is the assertion. If rehydration dropped the password evidence,
     * the policy would still be unsatisfied after TOTP and the flow would loop
     * asking for a password again -- so `['password', 'totp']` is only reachable
     * if the stored row survived the JSON round trip intact.
     */
    $handle = rehydrationFixture();

    $afterPassword = rehydrationFlow()->advance(
        new FlowRequest($handle, 'submit', ['password' => 'correct horse battery staple'], rehydrationBinding()),
    );

    expect($afterPassword)->toBeInstanceOf(Continuing::class);

    $stored = AuthAttempt::where('handle', $handle)->firstOrFail()->satisfied_factors;
    expect($stored)->toHaveCount(1);

    $final = rehydrationFlow()->advance(
        new FlowRequest($handle, 'submit', ['code' => rehydrationTotpCode()], rehydrationBinding()),
    );

    if (! $final instanceof Authenticated) {
        // A diagnostic rather than a bare assertion: when this test is un-skipped
        // the failure message should say WHICH screen the flow stopped on.
        $detail = $final instanceof Continuing
            ? sprintf(
                'step=%s offered=%s fields=%s errors=%s',
                $final->screen->step->value,
                implode(',', array_map(static fn ($o): string => $o->factorId, $final->screen->offeredFactors)),
                implode(',', array_map(static fn ($f): string => $f->name, $final->screen->fields)),
                (string) json_encode($final->screen->errors),
            )
            : 'no screen';

        throw new RuntimeException(sprintf('Expected Authenticated, got %s. %s', $final::class, $detail));
    }

    expect($final)->toBeInstanceOf(Authenticated::class)
        ->and($final->success->amr())->toBe(['password', 'totp'])
        ->and($final->success->userId)->toBe(7);
});

it('drops a stored row whose fields are the wrong shape rather than trusting it', function (string $field, mixed $bad): void {
    /*
     * The per-field guards. A malformed row must be DISCARDED, not coerced: a
     * missing factor_id read as '' would become a SatisfiedFactor carrying an
     * empty string, and the kernel would evaluate it as real evidence for a
     * factor that does not exist.
     *
     * Corruption is plausible here because this data round-trips through JSON in
     * a database column -- a partial write, a schema migration, or an older
     * encoder are all ordinary ways to arrive at a row of the wrong shape.
     *
     * The assertion is that the attempt is NOT authenticated by the tampered
     * evidence alone: the flow still demands the password it never really saw.
     */
    $handle = rehydrationFixture();

    rehydrationFlow()->advance(
        new FlowRequest($handle, 'submit', ['password' => 'correct horse battery staple'], rehydrationBinding()),
    );

    $attempt = AuthAttempt::where('handle', $handle)->firstOrFail();
    $rows = $attempt->satisfied_factors ?? [];

    if ($rows === []) {
        throw new RuntimeException('Fixture stored no evidence to corrupt.');
    }

    $row = $rows[0];
    $row[$field] = $bad;
    $attempt->update(['satisfied_factors' => [$row]]);

    $result = rehydrationFlow()->advance(
        new FlowRequest($handle, 'submit', ['code' => rehydrationTotpCode()], rehydrationBinding()),
    );

    // Not Authenticated: the corrupted password evidence was discarded, so the
    // all_of policy is still unsatisfied even though TOTP succeeded.
    expect($result)->not->toBeInstanceOf(Authenticated::class);
})->with([
    'factor_id not a string' => ['factor_id', 123],
    'credential_id not a string' => ['credential_id', 456],
    'kind not a string' => ['kind', 9],
    'strength not an int' => ['strength', 'knowledge'],
    'satisfied_at not a string' => ['satisfied_at', 1_700_000_000],
    'kind not a known case' => ['kind', 'telepathy'],
    'strength not a known case' => ['strength', 9_999],
]);

it('routes a selected factor to that factor driver, not the first-credential fallback', function (): void {
    /*
     * The defect this file first surfaced. verify() special-cased only
     * action === 'recover' and sent everything else to defaultFactorFor(), which
     * re-selected the FIRST active non-recovery credential on every step --
     * password. So a submitted TOTP code was handed to PasswordFactor and
     * truthfully refused, and no all_of policy could ever reach its second
     * factor.
     *
     * A RecordingGuard-style proxy is unnecessary here: only TotpFactor can
     * accept a TOTP code, so a satisfied result IS proof the submission reached
     * it rather than the password fallback.
     */
    $handle = rehydrationFixture();

    rehydrationFlow()->advance(
        new FlowRequest($handle, 'submit', ['password' => 'correct horse battery staple'], rehydrationBinding()),
    );

    $result = rehydrationFlow()->advance(
        new FlowRequest($handle, 'submit', ['factor' => 'totp', 'code' => rehydrationTotpCode()], rehydrationBinding()),
    );

    expect($result)->toBeInstanceOf(Authenticated::class);
});

it('refuses a factor the server is not currently offering', function (string $requested): void {
    /*
     * Client selection is a choice among what the server offers, never a lookup
     * key. 'webauthn_platform' is not registered; 'recovery_code' is registered
     * but deliberately excluded, because recovery is its own action with its own
     * constrained outcome and must not be reachable through the ordinary satisfy
     * path; 'password' is registered AND held by this user but already satisfied
     * on this attempt.
     *
     * All three refuse identically. A client that could distinguish them would
     * have a registry oracle and an evidence oracle in the same response.
     */
    $handle = rehydrationFixture();

    rehydrationFlow()->advance(
        new FlowRequest($handle, 'submit', ['password' => 'correct horse battery staple'], rehydrationBinding()),
    );

    $result = rehydrationFlow()->advance(
        new FlowRequest($handle, 'submit', ['factor' => $requested, 'code' => rehydrationTotpCode()], rehydrationBinding()),
    );

    expect($result)->toBeInstanceOf(Continuing::class)
        ->and($result)->not->toBeInstanceOf(Authenticated::class);
})->with([
    'unregistered driver' => 'webauthn_platform',
    'registered but not offered' => 'recovery_code',
    'already satisfied on this attempt' => 'password',
]);

it('cannot advance the policy by re-submitting an already-satisfied factor', function (): void {
    /*
     * The stronger half of the case above. Refusing the SELECTION is not enough
     * on its own -- what matters is that the evidence ledger does not grow. If a
     * satisfied factor could be re-submitted and re-recorded, an all_of policy
     * would be satisfiable by one credential presented twice, which is the whole
     * guarantee multi-factor exists to make.
     */
    $handle = rehydrationFixture();

    rehydrationFlow()->advance(
        new FlowRequest($handle, 'submit', ['password' => 'correct horse battery staple'], rehydrationBinding()),
    );

    rehydrationFlow()->advance(
        new FlowRequest($handle, 'submit', ['password' => 'correct horse battery staple'], rehydrationBinding()),
    );

    $stored = AuthAttempt::where('handle', $handle)->firstOrFail()->satisfied_factors ?? [];

    expect($stored)->toHaveCount(1)
        ->and(array_column($stored, 'factor_id'))->toBe(['password']);
});

it('discards only the malformed row, not the evidence after it', function (): void {
    /*
     * `continue`, not `break`. A corrupt row must cost exactly itself.
     *
     * With `break` the loop abandons the whole ledger at the first bad row, so a
     * single malformed entry silently discards every valid factor recorded after
     * it. On an all_of policy that is a lockout, and on a partially-evaluated one
     * it is worse: assurance is computed from a truncated evidence set that looks
     * complete. A single-row fixture cannot tell the two apart, which is why this
     * needs two.
     */
    $handle = rehydrationFixture();

    rehydrationFlow()->advance(
        new FlowRequest($handle, 'submit', ['password' => 'correct horse battery staple'], rehydrationBinding()),
    );

    $attempt = AuthAttempt::where('handle', $handle)->firstOrFail();
    $rows = $attempt->satisfied_factors ?? [];

    if ($rows === []) {
        throw new RuntimeException('Fixture stored no evidence.');
    }

    /*
     * TWO corrupt rows, because there are two `continue` statements and they
     * guard different things. The first rejects a row of the wrong SHAPE; the
     * second rejects a well-shaped row naming an enum case that does not exist.
     * A fixture that trips only one leaves the other's continue-vs-break
     * indistinguishable -- which is exactly what the first version of this test
     * did, and the probe caught it.
     */
    $wrongShape = $rows[0];
    $wrongShape['factor_id'] = 123;

    $unknownCase = $rows[0];
    $unknownCase['kind'] = 'telepathy';

    // Both corrupt rows FIRST, the genuine password evidence last.
    $attempt->update(['satisfied_factors' => [$wrongShape, $unknownCase, $rows[0]]]);

    $result = rehydrationFlow()->advance(
        new FlowRequest($handle, 'submit', ['factor' => 'totp', 'code' => rehydrationTotpCode()], rehydrationBinding()),
    );

    // The surviving password row still satisfies the all_of policy alongside TOTP.
    expect($result)->toBeInstanceOf(Authenticated::class);
});
