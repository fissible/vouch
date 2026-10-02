<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\CredentialLockManager;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/**
 * #19. What a credential identity is, asserted where it enters.
 *
 * `auth_credentials.id` is `$table->id()` -- an unsigned bigint -- so the database decides
 * credential identity numerically, and `9` and `09` are the SAME row. Meanwhile
 * `auth_token_credentials.credential_id` is varchar(191), so a persisted proof CAN carry a
 * spelling the credential table cannot mean.
 *
 * Measured consequences of leaving the two disagreeing: locking a non-numeric id fails outright
 * on PostgreSQL with `SQLSTATE[22P02] invalid input syntax for type bigint`, and a non-canonical
 * numeric spelling silently matches a different credential on MySQL. Both are reached from a
 * value a host or a future driver wrote, not from anything the shipped drivers do -- they all
 * write `(string) $credential->id`.
 *
 * So the domain is asserted at the two boundaries the value crosses rather than left to the
 * engine to discover: when a proof is persisted, and before a credential is locked. These tests
 * do not say WHERE the check lives or what it is called, only that both boundaries refuse.
 */
function nonCanonicalCredentialIds(): array
{
    return [
        // Leading zeros: the spelling the old docblock claimed named a different credential.
        'leading zero' => '09',
        'several leading zeros' => '007',
        // Not a decimal integer at all. This is the one that throws on PostgreSQL today.
        'non numeric' => 'cred-1',
        'decimal point' => '9.0',
        'hexadecimal' => '0x9',
        'exponent' => '9e0',
        // Signs and spacing: accepted by a naive is_numeric(), rejected by the column.
        'leading plus' => '+9',
        'negative' => '-1',
        'leading space' => ' 9',
        'trailing space' => '9 ',
        // Zero is not a credential: the key is auto-incrementing and starts at one.
        'zero' => '0',
        // A full-width digit is a digit to a human and not to the column.
        'full width digit' => "\u{FF11}",
        // Above the unsigned bigint the key column is, so no row can ever carry it.
        'above the column range' => '18446744073709551616',
    ];
}

it('refuses to persist a proof carrying a credential id the credential table cannot mean', function (string $credentialId): void {
    /*
     * Through store(), not through whatever validates for it: the boundary is "a proof is
     * persisted", and an implementation is free to put the check wherever it reaches that.
     */
    expect(fn () => app(TokenAssuranceRecord::class)->store(
        'sanctum',
        'token-1',
        SubjectKey::forConfiguredUser(1),
        null,
        ActorKind::Human,
        [satisfiedFactorWithCredential($credentialId)],
    ))->toThrow(InvalidArgumentException::class);

    // Nothing persisted, so a refusal is not a partial write.
    expect(DB::table('auth_token_credentials')->count())->toBe(0);
    expect(DB::table('auth_token_assurances')->count())->toBe(0);
})->with(nonCanonicalCredentialIds());

it('names the offending credential id when it refuses', function (): void {
    /*
     * #55's precedent: a refusal that does not quote the value leaves the operator to guess which
     * of several factors carried it. The empty-string refusal this replaces named nothing.
     */
    try {
        app(TokenAssuranceRecord::class)->store(
            'sanctum',
            'token-1',
            SubjectKey::forConfiguredUser(1),
            null,
            ActorKind::Human,
            [satisfiedFactorWithCredential('cred-1')],
        );
    } catch (InvalidArgumentException $e) {
        expect($e->getMessage())->toContain('cred-1');

        return;
    }

    throw new RuntimeException('The store accepted a non-canonical credential id.');
});

it('persists a proof whose credential ids are canonical', function (string $credentialId): void {
    /*
     * The positive control, and it has to cover the column's own extremes: a refusal that also
     * rejected '1' or the largest id the column can hold would pass every assertion above while
     * making the package unusable.
     */
    app(TokenAssuranceRecord::class)->store(
        'sanctum',
        'token-' . $credentialId,
        SubjectKey::forConfiguredUser(1),
        null,
        ActorKind::Human,
        [satisfiedFactorWithCredential($credentialId)],
    );

    expect(DB::table('auth_token_credentials')->where('credential_id', $credentialId)->count())->toBe(1);
})->with([
    'one' => '1',
    'single digit' => '9',
    'many digits' => '1234567890',
    'the largest the column holds' => '18446744073709551615',
]);

it('refuses a non-canonical credential id before it reaches the database', function (string $credentialId): void {
    /*
     * The second boundary. Today this reaches the engine and the engine decides: PostgreSQL throws
     * SQLSTATE[22P02] and MySQL compares numerically and matches the wrong row. Neither is a
     * refusal, and the PostgreSQL one is an unhandled driver error rather than a stated contract.
     *
     * Asserting InvalidArgumentException rather than "any throwable" is the point: a QueryException
     * would still be a throw, and would still be the bug.
     */
    expect(fn () => app(CredentialLockManager::class)->acquire(
        DB::connection(),
        SubjectKey::forConfiguredUser(1),
        [$credentialId],
    ))->toThrow(InvalidArgumentException::class);
})->with(nonCanonicalCredentialIds());

it('locks canonical credential ids without complaint', function (): void {
    // Positive control for the lock path, inside a transaction because that is where locks live.
    DB::transaction(function (): void {
        app(CredentialLockManager::class)->acquire(
            DB::connection(),
            SubjectKey::forConfiguredUser(1),
            ['1', '9', '1234567890'],
        );
    });

    expect(true)->toBeTrue();
});

it('orders credential ids as decimal strings, which is the lock order and not an identity claim', function (): void {
    /*
     * The order contract is unchanged by #19 and is deliberately pinned here, because the fix
     * corrects a docblock that described this function as preserving opaque string IDENTITY. It
     * does not: it is the single deterministic ORDER every path that locks credentials must use.
     *
     * String order, so '10' sorts before '9'. That is not database primary-key order, and the
     * difference is the reason the function exists.
     */
    expect(CredentialLockManager::canonicalCredentialIds(['9', '10', '9', '100']))
        ->toBe(['10', '100', '9']);
});

it('no longer claims two spellings of one number name different credentials', function (): void {
    /*
     * The docblock is the artefact #19 is about: it tells the next reader that string identity is
     * preserved end to end, which the schema does not do. A comment cannot be asserted by
     * behaviour, so it is asserted as text -- narrowly, on the specific false claim rather than on
     * any wording around it.
     *
     * The needle is built rather than written, so this file does not contain the thing it asserts
     * is absent.
     */
    $source = (string) file_get_contents((new ReflectionClass(CredentialLockManager::class))->getFileName());

    expect($source)->not->toContain('`9` and `0' . '9`' . "\n" . ' * name different credentials');
    expect($source)->not->toContain('are opaque strings');

    // Positive control: the file was actually read and does contain the surrounding docblock.
    expect($source)->toContain('canonicalCredentialIds()');
});

function satisfiedFactorWithCredential(string $credentialId): SatisfiedFactor
{
    return new SatisfiedFactor(
        'password',
        $credentialId,
        FactorKind::Knowledge,
        FactorStrength::Knowledge,
        false,
        false,
        false,
        null,
        new DateTimeImmutable('2026-08-13T10:00:00+00:00'),
    );
}
