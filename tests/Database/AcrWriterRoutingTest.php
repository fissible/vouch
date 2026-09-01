<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\SelfService\CredentialSelfService;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Fissible\Vouch\Tests\Support\Assurance\GenerousVocabulary;
use Fissible\Vouch\Tests\Support\Assurance\InvertedVocabulary;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;

uses(DatabaseMigrations::class);

/*
 * Issue #10 -- every writer of the `acr` projection uses the HOST's vocabulary.
 *
 * The structural guard in tests/Arch cannot establish this. A writer that
 * constructs its own NistAssuranceVocabulary touches no container and declares
 * no ambient dependency, yet silently ignores the host's choice everywhere the
 * projection is written. Under the suite's default binding -- which IS
 * NistAssuranceVocabulary -- nothing would fail.
 *
 * So these drive the real paths with a vocabulary that names the same facts the
 * OPPOSITE way. Every assertion below is a value NistAssuranceVocabulary cannot
 * produce for the evidence in question, which is what makes it falsifiable.
 *
 * These assert the stored OUTCOME rather than the mechanism, with ONE
 * deliberate exception. Reusing the acr AuthSuccess already carries was
 * considered and is now refused by the contract: that string names
 * $success->facts, while the stored proof is built from $success->factors, and
 * nothing enforces that the two describe the same evidence. The last test in
 * this file is the one that forecloses it.
 */

/** Bind a vocabulary and discard anything already built with another. */
function bindVocabulary(AssuranceVocabulary $vocabulary): void
{
    app()->instance(AssuranceVocabulary::class, $vocabulary);

    foreach ([SessionLifecycle::class, TokenAssuranceRecord::class, CredentialSelfService::class,
        \Fissible\Vouch\Assurance\EvidenceComparator::class] as $service) {
        app()->forgetInstance($service);
    }
}

function bindInvertedVocabulary(): void
{
    bindVocabulary(new InvertedVocabulary());
}

/** @return list<\Fissible\Vouch\Kernel\Factor\SatisfiedFactor> */
function twoCredentialFactors(string $first = 'cred-1', string $second = 'cred-2'): array
{
    return [
        evidenceFactor('password', '2026-09-01T10:00:00+00:00', FactorStrength::Knowledge, $first),
        evidenceFactor('totp', '2026-09-01T10:01:00+00:00', FactorStrength::Possession, $second),
    ];
}

it('writes the session projection with the host vocabulary', function (): void {
    /*
     * This passes both BEFORE and AFTER the change, and that is deliberate --
     * the ambient lookup also honours a rebound vocabulary, so no arrangement
     * of this test could make it fail today. Its job is not to demonstrate RED.
     * It fails only if the fix ignores the host's choice: a writer that
     * constructs NistAssuranceVocabulary itself, or reads a level from anywhere
     * the host cannot influence. That failure mode has no other detector.
     */
    bindInvertedVocabulary();

    $factors = twoCredentialFactors();

    /*
     * Two distinct credentials: Nist names this aal2, the host's vocabulary
     * names it aal1. The acr on AuthSuccess is what AuthFlow would have
     * produced from the same injected vocabulary, so an implementation reusing
     * it and one re-deriving both land on aal1 -- and a hard-coded Nist lands
     * on aal2.
     */
    app(SessionLifecycle::class)->establish(new AuthSuccess(
        userId: 1,
        factors: $factors,
        facts: AssuranceFacts::fromFactors($factors),
        acr: 'aal1',
        boundContext: 'session',
        tenantId: null,
    ));

    expect(AuthSession::query()->where('user_id', 1)->value('acr'))->toBe('aal1');
});

it('names the factors it persisted, not the acr it was handed', function (): void {
    /*
     * SessionLifecycle re-derives rather than reusing AuthSuccess::$acr, and
     * this is why. The acr on AuthSuccess names $success->facts; the row's
     * assurance_proof is built from $success->factors. Nothing enforces that
     * those two describe the same thing.
     *
     * So this hands over a deliberately contradictory AuthSuccess: two
     * credentials in `factors` -- which the host vocabulary names aal1 -- with
     * `facts` and `acr` describing a single-credential login the same
     * vocabulary would name aal2. An implementation that stored the string it
     * was given persists aal2 beside a proof that derives aal1, which is the
     * column-disagrees-with-proof defect Task 2a removed.
     *
     * This is the one test that distinguishes the two candidate
     * implementations, and it is why the contract pins re-derivation.
     */
    bindInvertedVocabulary();

    $factors = twoCredentialFactors();
    $unrelated = [evidenceFactor('password', '2026-09-01T10:00:00+00:00', FactorStrength::Knowledge, 'cred-9')];

    app(SessionLifecycle::class)->establish(new AuthSuccess(
        userId: 1,
        factors: $factors,
        facts: AssuranceFacts::fromFactors($unrelated),
        acr: 'aal2',
        boundContext: 'session',
        tenantId: null,
    ));

    expect(AuthSession::query()->where('user_id', 1)->value('acr'))->toBe('aal1');
});

it('writes the token projection with the host vocabulary', function (): void {
    // Passes before and after, for the reason given above.
    bindInvertedVocabulary();

    app(TokenAssuranceRecord::class)->store(
        'sanctum',
        'token-1',
        SubjectKey::of(configuredUserProvider(), 1),
        null,
        ActorKind::Human,
        twoCredentialFactors(),
    );

    expect(stringValue(DB::table('auth_token_assurances')->where('token_key', 'token-1')->value('acr')))
        ->toBe('aal1');
});

it('rewrites the self-service projection with the host vocabulary', function (): void {
    /*
     * The remaining writer, and the one with no alternative source of a name:
     * it builds fresh evidence after removing a factor and must name it.
     *
     * GenerousVocabulary rather than the inverted one, for a reason worth
     * stating. Self-service gates its own operations at aal2 through the SAME
     * comparator that now takes the bound vocabulary, so a fixture naming the
     * acting session's two-credential proof aal1 refuses at the gate and never
     * reaches the rewrite -- the test would measure the gate rather than the
     * writer. This keeps the acting session sufficient while still departing
     * from the shipped vocabulary where it counts: one credential remains after
     * the removal, which Nist names aal1 and this names aal2.
     */
    acrRoutingUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    $password = AuthCredential::query()->where('user_id', 1)->where('type', 'password')->firstOrFail();

    $acting = AuthSession::create([
        'user_id' => 1,
        'session_binding' => str_pad('routing-selfservice', 64, 'a'),
        'amr' => ['password', 'totp'],
        'acr' => 'aal2',
        'assurance_proof' => sessionProofFrom(1, twoCredentialFactors((string) $password->id, (string) $totp->id)),
        'weakest_satisfied_at' => now(),
    ]);

    bindVocabulary(new GenerousVocabulary());

    expect(app(CredentialSelfService::class)->removeFactor($acting, $totp->id))
        ->toBe(\Fissible\Vouch\SelfService\SelfServiceOutcome::Completed);

    expect($acting->refresh()->acr)->toBe('aal2');
});

/** A user with a password credential and a verified identifier. */
function acrRoutingUser(int $userId = 1): void
{
    \Fissible\Vouch\Models\AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => now(),
    ]);

    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)
        ->enroll($userId, ['password' => 'old-password']);
}
