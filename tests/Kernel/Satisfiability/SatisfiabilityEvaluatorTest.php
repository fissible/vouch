<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Kernel\Policy\AllOf;
use Fissible\Vouch\Kernel\Policy\AnyOf;
use Fissible\Vouch\Kernel\Policy\FactorRequirement;
use Fissible\Vouch\Kernel\Policy\Requirement;
use Fissible\Vouch\Kernel\Satisfiability\SatisfiabilityEvaluator;

function factor(
    string $factorId,
    string $credentialId,
    FactorStrength $strength = FactorStrength::Possession,
    bool $userVerified = false,
    bool $phishingResistant = false,
    ?string $authenticatorId = null,
): SatisfiedFactor {
    return new SatisfiedFactor(
        factorId: $factorId,
        credentialId: $credentialId,
        kind: FactorKind::Possession,
        strength: $strength,
        isMultiFactor: $userVerified,
        userVerified: $userVerified,
        phishingResistant: $phishingResistant,
        authenticatorId: $authenticatorId,
        satisfiedAt: new DateTimeImmutable('2026-08-11T10:00:00+00:00'),
    );
}

it('satisfies a single leaf requirement', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('password')]),
        [factor('password', 'cred-1')],
    );

    expect($verdict->satisfied)->toBeTrue()
        ->and($verdict->usedFactors)->toHaveCount(1);
});

it('fails when the required factor is absent', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('totp')]),
        [factor('password', 'cred-1')],
    );

    expect($verdict->satisfied)->toBeFalse()
        ->and($verdict->usedFactors)->toBeEmpty();
});

it('refuses to count one credential as two factors', function (): void {
    $passkey = factor('passkey', 'cred-1', userVerified: true);

    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('passkey'), new FactorRequirement('passkey')]),
        [$passkey],
    );

    expect($verdict->satisfied)->toBeFalse();
});

it('accepts two distinct credentials of the same factor', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('passkey'), new FactorRequirement('passkey')]),
        [factor('passkey', 'cred-1'), factor('passkey', 'cred-2')],
    );

    expect($verdict->satisfied)->toBeTrue()
        ->and($verdict->usedFactors)->toHaveCount(2);
});

it('allows one credential to serve twice when distinctness is waived', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf(
            [new FactorRequirement('passkey'), new FactorRequirement('passkey')],
            requireDistinctCredentials: false,
        ),
        [factor('passkey', 'cred-1')],
    );

    expect($verdict->satisfied)->toBeTrue();
});

it('backtracks rather than greedily consuming the only match for another requirement', function (): void {
    // 'shared' matches both requirements; 'totp-only' matches only the second.
    // A greedy first-match pass assigns 'shared' to requirement one and then
    // has nothing left for requirement two.
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([
            new FactorRequirement('totp', minimumStrength: FactorStrength::Possession),
            new FactorRequirement('totp', minimumStrength: FactorStrength::PossessionStrong),
        ]),
        [
            factor('totp', 'cred-strong', FactorStrength::PossessionStrong),
            factor('totp', 'cred-weak', FactorStrength::Possession),
        ],
    );

    expect($verdict->satisfied)->toBeTrue();
});

it('rejects two credentials on the same authenticator when independence is required', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf(
            [new FactorRequirement('passkey'), new FactorRequirement('passkey')],
            requireIndependentAuthenticators: true,
        ),
        [
            factor('passkey', 'cred-1', authenticatorId: 'device-1'),
            factor('passkey', 'cred-2', authenticatorId: 'device-1'),
        ],
    );

    expect($verdict->satisfied)->toBeFalse();
});

it('accepts credentials on different authenticators', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf(
            [new FactorRequirement('passkey'), new FactorRequirement('passkey')],
            requireIndependentAuthenticators: true,
        ),
        [
            factor('passkey', 'cred-1', authenticatorId: 'device-1'),
            factor('passkey', 'cred-2', authenticatorId: 'device-2'),
        ],
    );

    expect($verdict->satisfied)->toBeTrue();
});

it('never lets a recovery code satisfy a policy', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('recovery_code')]),
        [factor('recovery_code', 'cred-1', FactorStrength::Recovery)],
    );

    expect($verdict->satisfied)->toBeFalse();
});

it('accepts a user-verified passkey alone under the mfa preset', function (): void {
    $mfa = new AnyOf([
        new AllOf([new FactorRequirement('passkey', userVerified: true)]),
        new AllOf(
            [new FactorRequirement('password'), new FactorRequirement('totp')],
            requireIndependentAuthenticators: true,
        ),
    ]);

    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        $mfa,
        [factor('passkey', 'cred-1', FactorStrength::PossessionStrong, userVerified: true)],
    );

    expect($verdict->satisfied)->toBeTrue()
        ->and($verdict->usedFactors)->toHaveCount(1);
});

it('rejects a passkey without user verification under the mfa preset', function (): void {
    $mfa = new AnyOf([
        new AllOf([new FactorRequirement('passkey', userVerified: true)]),
        new AllOf([new FactorRequirement('password'), new FactorRequirement('totp')]),
    ]);

    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        $mfa,
        [factor('passkey', 'cred-1', FactorStrength::PossessionStrong, userVerified: false)],
    );

    expect($verdict->satisfied)->toBeFalse();
});

it('accepts password plus totp under the mfa preset', function (): void {
    $mfa = new AnyOf([
        new AllOf([new FactorRequirement('passkey', userVerified: true)]),
        new AllOf([new FactorRequirement('password'), new FactorRequirement('totp')]),
    ]);

    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        $mfa,
        [
            factor('password', 'cred-1', FactorStrength::Knowledge),
            factor('totp', 'cred-2', FactorStrength::Possession),
        ],
    );

    expect($verdict->satisfied)->toBeTrue()
        ->and($verdict->usedFactors)->toHaveCount(2);
});

it('treats an unrecognised requirement type as unsatisfiable', function (): void {
    // The `default => []` arm of solve(). Without it, an unknown Requirement
    // implementation would fall through to whichever solver sits last in the
    // match, and be solved as if it were that shape.
    $unknown = new class implements Requirement {};

    $verdict = (new SatisfiabilityEvaluator())->evaluate($unknown, [factor('password', 'cred-1')]);

    expect($verdict->satisfied)->toBeFalse()
        ->and($verdict->usedFactors)->toBeEmpty();
});

it('accepts a phishing-resistant factor when the policy demands one', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('passkey', phishingResistant: true)]),
        [factor('passkey', 'cred-1', phishingResistant: true)],
    );

    expect($verdict->satisfied)->toBeTrue();
});

it('rejects a factor that is not phishing resistant when the policy demands one', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('passkey', phishingResistant: true)]),
        [factor('passkey', 'cred-1', phishingResistant: false)],
    );

    expect($verdict->satisfied)->toBeFalse();
});

it('treats phishing resistance as an exact match, not a threshold', function (): void {
    // A requirement of `false` means "must not be phishing resistant", not
    // "no constraint": a resistant factor does not match it.
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('passkey', phishingResistant: false)]),
        [factor('passkey', 'cred-1', phishingResistant: true)],
    );

    expect($verdict->satisfied)->toBeFalse();
});

it('ignores phishing resistance when the requirement leaves it unconstrained', function (): void {
    $evaluator = new SatisfiabilityEvaluator();
    $policy = new AllOf([new FactorRequirement('passkey')]);

    expect($evaluator->evaluate($policy, [factor('passkey', 'cred-1', phishingResistant: true)])->satisfied)->toBeTrue()
        ->and($evaluator->evaluate($policy, [factor('passkey', 'cred-2', phishingResistant: false)])->satisfied)->toBeTrue();
});

it('rejects a factor weaker than the required minimum strength', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('totp', minimumStrength: FactorStrength::PossessionStrong)]),
        [factor('totp', 'cred-1', FactorStrength::Possession)],
    );

    expect($verdict->satisfied)->toBeFalse()
        ->and($verdict->usedFactors)->toBeEmpty();
});

it('allows two credentials on one authenticator when independence is not required', function (): void {
    // Independence defaults to off, so a single device holding two distinct
    // credentials satisfies a two-factor policy.
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('passkey'), new FactorRequirement('passkey')]),
        [
            factor('passkey', 'cred-1', authenticatorId: 'device-1'),
            factor('passkey', 'cred-2', authenticatorId: 'device-1'),
        ],
    );

    expect($verdict->satisfied)->toBeTrue()
        ->and($verdict->usedFactors)->toHaveCount(2);
});

it('ignores authenticator independence for factors with no authenticator', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf(
            [new FactorRequirement('password'), new FactorRequirement('totp')],
            requireIndependentAuthenticators: true,
        ),
        [
            factor('password', 'cred-1', FactorStrength::Knowledge),
            factor('totp', 'cred-2', FactorStrength::Possession),
        ],
    );

    expect($verdict->satisfied)->toBeTrue();
});
