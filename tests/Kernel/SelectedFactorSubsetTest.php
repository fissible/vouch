<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Kernel\Policy\PolicyParser;
use Fissible\Vouch\Kernel\Satisfiability\SatisfiabilityEvaluator;

/*
 * 2.4 Task 2a — the selected set is a strict subset, and that is reachable.
 *
 * Framework-free on purpose: this is a property of the evaluator, and proving
 * it here costs nothing and cannot be broken by anything Laravel does.
 *
 * Vouch does NOT persist this set -- SelectedProofTest records why, and holds
 * the writer to the attempt's full satisfied set instead. The property is
 * pinned anyway, because the decision to persist the broader set is only
 * meaningful while the two can differ. If the evaluator ever started returning
 * everything it was given, that decision would quietly become a no-op, and the
 * comment explaining it would be describing a distinction that no longer
 * exists. This is what makes that visible.
 */

function subsetFactor(string $id, string $credentialId): SatisfiedFactor
{
    return new SatisfiedFactor(
        factorId: $id,
        credentialId: $credentialId,
        kind: FactorKind::Knowledge,
        strength: FactorStrength::Knowledge,
        isMultiFactor: false,
        userVerified: false,
        phishingResistant: false,
        authenticatorId: null,
        satisfiedAt: new DateTimeImmutable('2026-08-29T10:00:00+00:00'),
    );
}

it('selects only the branch that satisfied an any_of policy', function (): void {
    /*
     * Satisfy one factor of the first branch, then both of the second. The
     * attempt holds three factors; the policy used two. An all_of policy cannot
     * express this difference, which is exactly why relying on "the flow stops
     * when satisfied" was the wrong argument.
     */
    $document = ['any_of' => [
        ['all_of' => ['password', 'totp']],
        ['all_of' => ['email_otp', 'sms_otp']],
    ]];

    $satisfied = [
        subsetFactor('password', 'cred-1'),
        subsetFactor('email_otp', 'cred-2'),
        subsetFactor('sms_otp', 'cred-3'),
    ];

    $verdict = (new SatisfiabilityEvaluator())->evaluate((new PolicyParser())->parse($document), $satisfied);

    expect($verdict->satisfied)->toBeTrue()
        ->and(array_map(static fn (SatisfiedFactor $f): string => $f->factorId, $verdict->usedFactors))
        ->toEqualCanonicalizing(['email_otp', 'sms_otp'])
        ->and($verdict->usedFactors)->toHaveCount(2)
        ->and($satisfied)->toHaveCount(3);
});
