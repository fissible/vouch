<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\Mutations\ConsumeChallenge;
use Fissible\Vouch\Attempts\Mutations\DisableCredential;

/*
 * target() is the conflict-detection key, not a label. The store refuses a
 * transition carrying two mutations with the same target, so what this string
 * builds decides which pairs are rejected as conflicting -- a protocol value
 * that happens to be built by concatenation.
 */

it('gives each subject its own target', function (): void {
    // Drop the id and every challenge shares one target, so any two consumptions
    // in a single transition would be rejected as a conflict that is not one.
    expect((new ConsumeChallenge(1, 9))->target())
        ->not->toBe((new ConsumeChallenge(2, 9))->target());
});

it('separates target namespaces so a challenge cannot collide with a credential', function (): void {
    /*
     * The prefix is what keeps the id spaces apart. Without it, challenge 7 and
     * credential 7 share a target, and a transition that legitimately consumes a
     * challenge while disabling a credential -- exactly what a recovery-code
     * login does -- would be refused as conflicting.
     */
    expect((new ConsumeChallenge(7, 9))->target())
        ->not->toBe((new DisableCredential(7))->target());
});

it('gives the same subject the same target, so a genuine conflict is detected', function (): void {
    // The other direction: two mutations on one subject MUST collide, which is
    // what the store's conflict check relies on.
    expect((new ConsumeChallenge(7, 9))->target())
        ->toBe((new ConsumeChallenge(7, 11))->target());
});
