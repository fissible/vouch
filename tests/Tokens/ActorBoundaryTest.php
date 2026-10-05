<?php

declare(strict_types=1);

use Fissible\Vouch\Assurance\AssuranceReason;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\ResolvedToken;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Tokens\TokenGrant;
use Fissible\Vouch\Vouch;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * #9 and #24 are DEFERRALS, and this file is what makes a deferral mean something.
 *
 * Both issues ask for a ratified boundary rather than a feature: who may authorize a machine token
 * (#9), and whether an actor operating on behalf of a human is a third ActorKind (#24). The
 * decisions are recorded in the contract addendum, §3l and §3m. Deferring is a valid outcome; what
 * is not valid is leaving the question open while `actor_kind` ships, because the column is
 * persisted and a later answer then has to reinterpret rows already written.
 *
 * A decision in a document drifts. So the invariants the two decisions REST ON are asserted here,
 * and every one of them already holds -- this file goes green the day it is written. That makes it
 * a characterisation guard, and the risk with those is that they cannot fail: each case below was
 * therefore checked by breaking the thing it guards and watching it go red. The measurements are
 * recorded per case.
 */

it('has exactly the two actor kinds the decisions were made about', function (): void {
    /*
     * The load-bearing assertion for #24. `actor_kind` is a persisted varchar(16), so adding a case
     * is cheap in schema terms and expensive in meaning: every `match` over ActorKind grows a branch,
     * every row already written acquires an implied answer to "was this delegated?", and the
     * assurance rules have to say whether the new kind can satisfy a human requirement.
     *
     * #24's answer is that delegation is an ATTRIBUTE of a human record carrying delegate, principal
     * and authority -- a third case cannot hold three identities. This fails if someone adds one, so
     * the decision has to be revisited rather than bypassed.
     *
     * Measured, since a guard that passes the day it is written has to be shown capable of failing:
     * adding a third case reddens this and two others -- the issuance sweep below, and the
     * unrecognised-kind case, which stops being unrecognised.
     */
    expect(array_map(static fn (ActorKind $kind): string => $kind->value, ActorKind::cases()))
        ->toBe(['human', 'machine']);
});

it('refuses issuance for every actor kind that is not human', function (): void {
    /*
     * #9's boundary, asserted over `cases()` rather than over the Machine case by name: a third kind
     * added later must be refused by default rather than becoming issuable because nobody thought
     * about it. Deny-by-default is the whole shape of the decision.
     *
     * Measured: removing the guard in Vouch::issueToken() reddens this and the no-write case below.
     */
    $refused = [];

    foreach (ActorKind::cases() as $kind) {
        if ($kind === ActorKind::Human) {
            continue;
        }

        DB::beginTransaction();

        try {
            Vouch::issueToken(new TokenGrant(SubjectKey::forConfiguredUser(7), 'api', ['orders:read'], actor: $kind));
        } catch (\Fissible\Vouch\Tokens\IssuanceRefused $e) {
            // Narrowed deliberately: an earlier version caught Throwable and a mis-built grant's
            // TypeError satisfied it, so the test passed without the refusal ever happening.
            $refused[$kind->value] = $e->getMessage();
        } finally {
            DB::rollBack();
        }
    }

    expect(array_keys($refused))->toBe(['machine']);

    foreach ($refused as $message) {
        // Named, so an operator reading a log learns the boundary rather than guessing.
        expect(strtolower($message))->toContain('machine');
    }
});

it('writes nothing when it refuses a machine grant', function (): void {
    /*
     * #9's other half: issuance must not become the first thing that CREATES a machine identity.
     * Task 4 enforces existing machine records, and the way that invariant dies is a refusal that
     * has already written half a record.
     *
     * The refusal is identified by its own message, not merely by its type: measured, removing the
     * guard in Vouch::issueToken() does NOT redden a bare "nothing was written" assertion, because
     * issuance then fails further on for an unrelated reason and still writes nothing. So what this
     * pins is that the MACHINE refusal is what happened and that it left no row -- which is weaker
     * than "the write is unreachable" and is stated that way rather than overclaimed.
     */
    $counts = static fn (): array => [
        'assurances' => DB::table('auth_token_assurances')->count(),
        'credentials' => DB::table('auth_token_credentials')->count(),
    ];

    $before = $counts();

    DB::beginTransaction();

    try {
        Vouch::issueToken(new TokenGrant(SubjectKey::forConfiguredUser(7), 'api', ['orders:read'], actor: ActorKind::Machine));
        throw new RuntimeException('Issuance accepted a machine grant.');
    } catch (\Fissible\Vouch\Tokens\IssuanceRefused $e) {
        // Narrowed, and the message checked: a TypeError or a later unrelated failure would
        // otherwise prove nothing was written because nothing was attempted.
        expect(strtolower($e->getMessage()))->toContain('machine');
    } finally {
        DB::rollBack();
    }

    expect($counts())->toBe($before);
});

it('leaves a persisted actor kind it does not recognise with no assurance at all', function (): void {
    /*
     * The compatibility rule #24's deferral rests on, and the reason the deferral is safe. If
     * delegation ever becomes a persisted value, a deployment running older code will read rows it
     * has no case for -- and it must treat them as unreadable rather than as human.
     *
     * Already true, because the read path uses ActorKind::from() and lets the ValueError become
     * ProofMalformed. That is one refactor away from being false: tryFrom() with a Human fallback
     * would read a delegated record as a full human principal, which is the worst available answer.
     *
     * Measured: replacing from() with `tryFrom() ?? ActorKind::Human` reddens this and nothing else,
     * which is what makes it this file's own guard rather than a side effect of another.
     */
    $evidence = evidenceFor([evidenceFactor(credentialId: '7')], userId: 7);

    DB::table('auth_token_assurances')->insert([
        'issuer_key' => 'sanctum',
        'token_key' => 'token-1',
        'subject_key' => $evidence->subject->render(),
        'tenant_id' => null,
        'actor_kind' => 'delegate',
        'acr' => 'aal2',
        /*
         * A VALID proof, built through the real value object. Measured: with a hand-written
         * `{"factors": []}` this case passed even under a `tryFrom() ?? Human` fallback, because the
         * proof was malformed on its own and the unknown actor kind never decided anything. The
         * fixture has to be good everywhere except the one field under test.
         */
        'assurance_proof' => json_encode($evidence->toArray(), JSON_THROW_ON_ERROR),
        'weakest_satisfied_at' => $evidence->weakestSatisfiedAt(),
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    $read = app(TokenAssuranceRecord::class)->read(new ResolvedToken(
        'sanctum',
        'token-1',
        $evidence->subject,
        usable: true,
    ));

    expect($read->evidence)->toBeNull();
    expect($read->reason)->toBe(AssuranceReason::ProofMalformed);
});

it('does not rely on the token issuer to refuse a machine grant', function (): void {
    /*
     * #9 names this hazard and it is worth pinning rather than describing: the concrete issuer does
     * NOT inspect ActorKind and will mint whatever grant it is handed. So the refusal's LOCATION is
     * load-bearing. Someone who assumes the issuer checks could move or drop the guard in
     * Vouch::issueToken() and find every test still green -- except this one, which says in place
     * that the issuer is not a second line of defence.
     *
     * Asserted as source rather than behaviour because that is what the claim is about: the driver
     * has no ActorKind in it. A behavioural version would have to mint a machine token to prove the
     * issuer allows it, which is the thing the package refuses to have a path for.
     */
    $issuer = (string) file_get_contents(
        (new ReflectionClass(\Fissible\Vouch\Tokens\Drivers\SanctumTokenIssuer::class))->getFileName(),
    );

    expect($issuer)->not->toContain('ActorKind');

    // The positive control: the file was read and is the one meant.
    expect($issuer)->toContain('class SanctumTokenIssuer');
});
