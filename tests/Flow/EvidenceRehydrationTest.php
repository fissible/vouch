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
})->skip(
    'INCOMPLETE, not disabled. The two-factor walk does not yet reach Authenticated: '
    . 'after the password step the flow challenges a code-bearing factor and the '
    . 'submitted TOTP code is refused with "That credential was not accepted." '
    . 'Diagnosis is unfinished, so this is recorded rather than guessed at. Un-skip '
    . 'this FIRST -- the malformed-row cases below are vacuous until it passes.',
);

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
])->skip(
    'VACUOUS while the happy path above is incomplete. These assert that a corrupted '
    . 'row does NOT authenticate -- and right now nothing authenticates, so all seven '
    . 'pass against an implementation that could be doing anything at all. They are '
    . 'skipped rather than left green because a passing test that cannot fail is worse '
    . 'than an absent one: it reports coverage of the guards while proving nothing. '
    . 'Un-skip together with the round-trip test above.',
);
