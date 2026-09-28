<?php

declare(strict_types=1);

/*
 * Evaluates a deliberately wide policy in a FRESH process under a memory limit the
 * caller sets.
 *
 * Six requirements over twelve credentials. A depth-first search stops at the first
 * complete assignment and answers in a few kilobytes; materialising the cartesian
 * product first cost 11.4 MB at five requirements over ten credentials and
 * exhausted 128 MB at six over twelve.
 *
 * In a subprocess rather than inline, because the regression is only OBSERVABLE as
 * memory exhaustion, and a test that observes it by dying needs a limit of its own.
 * Asserting it inline made the whole suite's `memory_limit` load-bearing for one
 * test: the pin could not be raised however close the suite came to it, and any
 * run that raised it -- the mutation campaign does, to 4G -- left this guard
 * reporting green while no longer guarding anything.
 *
 * Nothing framework-shaped is loaded. The Kernel is framework-free and this proves
 * it: an autoloader and the evaluator are the whole environment.
 *
 * Usage: php -d memory_limit=128M wide-policy-evaluation.php <package-root>
 */

require $argv[1] . '/vendor/autoload.php';

use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Kernel\Policy\AllOf;
use Fissible\Vouch\Kernel\Policy\FactorRequirement;
use Fissible\Vouch\Kernel\Satisfiability\SatisfiabilityEvaluator;

$pool = [];

for ($i = 1; $i <= 12; $i++) {
    $pool[] = new SatisfiedFactor(
        factorId: 'passkey',
        credentialId: 'cred-' . $i,
        kind: FactorKind::Possession,
        strength: FactorStrength::Possession,
        isMultiFactor: false,
        userVerified: false,
        phishingResistant: false,
        authenticatorId: null,
        satisfiedAt: new DateTimeImmutable('2026-08-11T10:00:00+00:00'),
    );
}

$verdict = (new SatisfiabilityEvaluator())->evaluate(
    new AllOf(array_fill(0, 6, new FactorRequirement('passkey'))),
    $pool,
);

/*
 * The used-factor count rather than a bare "ok": a search that answered by
 * accident, or one that stopped early with an incomplete assignment, prints a
 * different number rather than the same success.
 */
echo $verdict->satisfied ? count($verdict->usedFactors) : 'unsatisfied', PHP_EOL;
