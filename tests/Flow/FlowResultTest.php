<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\Authenticated;
use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Flow\FlowResult;
use Fissible\Vouch\Flow\RecoveryGraceStarted;
use Fissible\Vouch\Flow\UnknownFlowResult;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Kernel\Screen\ScreenSpec;

function flowBlankScreen(AuthStep $step = AuthStep::Identify): ScreenSpec
{
    return new ScreenSpec($step, [], [], null, [], null);
}

function flowSatisfiedFactor(string $id = 'password'): SatisfiedFactor
{
    return new SatisfiedFactor(
        factorId: $id,
        credentialId: '7',
        kind: FactorKind::Knowledge,
        strength: FactorStrength::Knowledge,
        isMultiFactor: false,
        userVerified: false,
        phishingResistant: false,
        authenticatorId: null,
        satisfiedAt: new DateTimeImmutable('2026-08-13T10:00:00+00:00'),
    );
}

it('reads a string field, or null when absent or the wrong type', function (): void {
    // Input arrives from a request body; the flow must not trust its shape.
    $request = new FlowRequest(
        handle: null,
        action: 'submit',
        input: ['code' => '123456', 'nested' => ['not', 'a', 'string']],
        boundContext: 'binding',
        clientIp: null,
        clientUserAgent: null,
    );

    expect($request->string('code'))->toBe('123456')
        ->and($request->string('nested'))->toBeNull()
        ->and($request->string('missing'))->toBeNull();
});

it('derives the amr from the satisfied factors, in order', function (): void {
    $success = new AuthSuccess(
        userId: 7,
        factors: [flowSatisfiedFactor('password'), flowSatisfiedFactor('totp')],
        facts: AssuranceFacts::fromFactors([flowSatisfiedFactor('password'), flowSatisfiedFactor('totp')]),
        acr: 'aal2',
        boundContext: 'binding',
    );

    expect($success->amr())->toBe(['password', 'totp']);
});

it('carries a screen on every variant, so serialization never inspects state', function (): void {
    $success = new AuthSuccess(7, [flowSatisfiedFactor()], AssuranceFacts::fromFactors([flowSatisfiedFactor()]), 'aal1', 'b');

    expect((new Continuing(flowBlankScreen()))->screen)->toBeInstanceOf(ScreenSpec::class)
        ->and((new Authenticated($success, flowBlankScreen()))->screen)->toBeInstanceOf(ScreenSpec::class)
        ->and((new RecoveryGraceStarted(7, 'b', flowBlankScreen(AuthStep::Enroll)))->screen)
        ->toBeInstanceOf(ScreenSpec::class);
});

it('carries the handle on Continuing, and permits none', function (): void {
    /*
     * A client beginning an attempt has no handle yet, so Continuing must
     * supply one. A refusal for an unknown handle must supply none: echoing
     * one back would let a caller learn which handles exist.
     */
    expect((new Continuing(flowBlankScreen(), 'a-handle'))->handle)->toBe('a-handle')
        ->and((new Continuing(flowBlankScreen()))->handle)->toBeNull();
});

it('names an unhandled variant rather than describing it vaguely', function (): void {
    /*
     * PHP has no sealed interfaces, which is why DatabaseAttemptStore throws
     * UnknownMutation rather than skipping a type it does not recognise. The
     * same hazard applies here, and the consequence is worse: falling through
     * on an unrecognised result would skip session rotation on a successful
     * authentication.
     */
    $rogue = new class implements FlowResult {};

    expect(fn () => throw UnknownFlowResult::for($rogue))
        ->toThrow(UnknownFlowResult::class, $rogue::class);
});
