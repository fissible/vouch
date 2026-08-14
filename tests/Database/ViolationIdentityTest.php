<?php

declare(strict_types=1);

use Fissible\Vouch\Persistence\ChallengeTargetViolation;
use Fissible\Vouch\Persistence\IdentifierLinkageViolation;
use Fissible\Vouch\Persistence\ValueBoundViolation;

/*
 * The violation classes had NO coverage -- 39 mutations, none tested -- while
 * tests/Database/{ChallengeTarget,IdentifierLinkage,ValueBounds}Test all pass.
 *
 * Those prove the guards REFUSE. These prove Vouch says WHICH invariant was
 * broken. They are separate contracts, and only the second one is what an
 * operator reads at three in the morning: five ChallengeTargetViolation
 * factories are interchangeable to a test that asserts only the exception class,
 * so "credential belongs to another user" and "credential does not exist" could
 * swap places unnoticed. Those are opposite investigations.
 *
 * Each message must therefore name its own invariant AND the entity involved.
 */

it('names a distinct invariant for every challenge-target violation', function (): void {
    $messages = [
        ChallengeTargetViolation::targetRequired('totp')->getMessage(),
        ChallengeTargetViolation::missing(11)->getMessage(),
        ChallengeTargetViolation::disabled(22)->getMessage(),
        ChallengeTargetViolation::foreignUser(33, 7)->getMessage(),
        ChallengeTargetViolation::notIdentifierLinked(44)->getMessage(),
    ];

    // No two violations may read the same. Distinctness is the property; a
    // factory that fell through to another one would collapse the count.
    expect(array_unique($messages))->toHaveCount(5)
        ->and($messages[0])->toContain('totp')
        ->and($messages[1])->toContain('11')
        ->and($messages[2])->toContain('22')
        ->and($messages[3])->toContain('33')
        ->and($messages[4])->toContain('44');
});

it('distinguishes an unidentified attempt from one owned by another user', function (): void {
    /*
     * The live predicate at ChallengeTargetViolation:47 --
     * `$attemptUserId === null ? '...' : (string) $attemptUserId`. Inverted, an
     * attempt with no identified user reports a user id, and an attempt owned by
     * someone else reports "no identified user". Both readings look like
     * plausible diagnostics and each sends the investigation the wrong way: one
     * invents an account that was never involved, the other hides the account
     * that was.
     */
    $anonymous = ChallengeTargetViolation::foreignUser(33, null)->getMessage();
    $owned = ChallengeTargetViolation::foreignUser(33, 7)->getMessage();

    expect($anonymous)->toContain('no identified user')
        ->and($anonymous)->not->toContain('(7)')
        ->and($owned)->toContain('7')
        ->and($owned)->not->toContain('no identified user');
});

it('names a distinct invariant for every identifier-linkage violation', function (): void {
    $messages = [
        IdentifierLinkageViolation::missing(11)->getMessage(),
        IdentifierLinkageViolation::crossUser(7, 8)->getMessage(),
        IdentifierLinkageViolation::unverified(22)->getMessage(),
        IdentifierLinkageViolation::frozen(33)->getMessage(),
    ];

    expect(array_unique($messages))->toHaveCount(4)
        // crossUser carries BOTH user ids: which one owns the credential and
        // which owns the identifier is the entire content of that violation.
        ->and($messages[1])->toContain('7')
        ->and($messages[1])->toContain('8');
});

it('reports the model, attribute and bound of a value-bound violation', function (): void {
    /*
     * These carry four operands. A message that named the attribute but not the
     * model, or the actual length but not the limit, leaves the operator unable
     * to tell whether the bound or the input is wrong.
     */
    $tooLong = ValueBoundViolation::tooLong('AuthIdentifier', 'value', 255, 300)->getMessage();
    $notAscii = ValueBoundViolation::notAscii('AuthIdentifier', 'value')->getMessage();

    expect($tooLong)->toContain('AuthIdentifier')
        ->and($tooLong)->toContain('value')
        ->and($tooLong)->toContain('255')
        ->and($tooLong)->toContain('300')
        ->and($notAscii)->toContain('AuthIdentifier')
        ->and($notAscii)->toContain('value')
        ->and($notAscii)->not->toBe($tooLong);
});
