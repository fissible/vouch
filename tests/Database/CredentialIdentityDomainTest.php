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
 *
 * @return array<string, string>
 */
/**
 * Credential queries ATTEMPTED while $work runs that carry one of $credentialIds.
 *
 * Attempted, not completed: Laravel throws before logQuery() runs, so the query log cannot see a
 * statement the database rejected. Measured -- an implementation that sent 'cred-1' to PostgreSQL
 * inside a savepoint, caught 22P02 and translated it satisfied a query-log assertion completely.
 *
 * Scoped to the supplied ids rather than to the table, because the table alone forbids correct
 * work: an unrelated, non-locking credential count for another user is legitimate on this path and
 * failed 17 assertions when the filter was the table name.
 *
 * @param  list<string>  $credentialIds
 * @return list<string>
 */
function attemptedCredentialQueriesFor(array $credentialIds, Closure $work): array
{
    $seen = [];

    DB::connection()->beforeExecuting(static function (string $query, array $bindings) use ($credentialIds, &$seen): void {
        if (! str_contains($query, 'auth_credentials')) {
            return;
        }

        foreach ($bindings as $binding) {
            if (in_array((string) $binding, $credentialIds, true)) {
                $seen[] = $query;

                return;
            }
        }
    });

    try {
        $work();
    } catch (InvalidArgumentException $e) {
        $seen[] = 'REFUSED: ' . $e->getMessage();
    }

    return $seen;
}

/**
 * Every spelling of a credential id the credential table cannot mean.
 *
 * @return array<string, string>
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
        /*
         * A trailing newline, because `$` in a PCRE pattern matches before a final one. Measured: a
         * validator written as /\A[1-9][0-9]*$/ accepted "9\n" and passed it to the credential
         * query while satisfying every other case here.
         */
        'trailing newline' => "9\n",
        // Empty, which the store already refused before #19 and the lock path did not.
        'empty' => '',
        /*
         * Zero. Rejected because the adopted contract is a POSITIVE identity -- not because zero
         * cannot be stored: measured, SQLite and PostgreSQL both accept a credential row with id 0.
         * So this is a deliberate compatibility boundary for an imported zero-id credential, not an
         * impossibility.
         */
        'zero' => '0',
        // A full-width digit is a digit to a human and not to the column.
        'full width digit' => "\u{FF11}",
        /*
         * Above the range every supported engine can actually store. The MySQL column is unsigned,
         * but SQLite's INTEGER PRIMARY KEY and PostgreSQL's bigserial are SIGNED, and both reject
         * an insert past the signed maximum. Measured: MySQL accepts 18446744073709551615 and then
         * Eloquent reads it back as 9223372036854775807, which is identity corruption rather than a
         * larger range. So the portable domain stops at the signed maximum and these are outside it.
         */
        'just above the portable maximum' => '9223372036854775808',
        'far above the portable maximum' => '18446744073709551616',
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
    // The largest id every supported engine can store and read back unchanged.
    'the portable maximum' => '9223372036854775807',
]);

it('refuses a proof when any one of its factors carries a bad credential id', function (): void {
    // Measured: an implementation checking only the first factor accepted and persisted ['1', '09'].
    expect(fn () => app(TokenAssuranceRecord::class)->store(
        'sanctum',
        'token-1',
        SubjectKey::forConfiguredUser(1),
        null,
        ActorKind::Human,
        [satisfiedFactorWithCredential('1'), satisfiedFactorWithCredential('09')],
    ))->toThrow(InvalidArgumentException::class);

    expect(DB::table('auth_token_credentials')->count())->toBe(0);
    expect(DB::table('auth_token_assurances')->count())->toBe(0);
});

it('leaves an existing proof intact when its replacement is refused', function (): void {
    /*
     * store() replaces by deleting then inserting. Measured: validating AFTER the delete rejects a
     * bad replacement and takes the previous proof with it.
     *
     * Counts cannot establish this. A mutant that cleared assurance_proof before throwing passed,
     * and so did one that silently returned instead of refusing -- the first because only rows were
     * counted, the second because the refusal was swallowed. So the row is compared by content and
     * the refusal is required.
     */
    app(TokenAssuranceRecord::class)->store(
        'sanctum',
        'token-1',
        SubjectKey::forConfiguredUser(1),
        null,
        ActorKind::Human,
        [satisfiedFactorWithCredential('7')],
    );

    $before = DB::table('auth_token_assurances')->orderBy('token_key')->get()->map(fn (object $row): array => (array) $row)->all();
    $beforeMappings = DB::table('auth_token_credentials')->orderBy('credential_id')->pluck('credential_id')->all();

    expect($before)->toHaveCount(1);
    expect($beforeMappings)->toBe(['7']);

    expect(fn () => app(TokenAssuranceRecord::class)->store(
        'sanctum',
        'token-1',
        SubjectKey::forConfiguredUser(1),
        null,
        ActorKind::Human,
        [satisfiedFactorWithCredential('09')],
    ))->toThrow(InvalidArgumentException::class);

    $after = DB::table('auth_token_assurances')->orderBy('token_key')->get()->map(fn (object $row): array => (array) $row)->all();

    expect($after)->toBe($before);
    expect(DB::table('auth_token_credentials')->orderBy('credential_id')->pluck('credential_id')->all())->toBe($beforeMappings);
});

it('refuses a non-canonical credential id before it reaches the database', function (string $credentialId): void {
    /*
     * The second boundary, and neither the exception type nor the query log alone establishes it.
     * Measured: translating PostgreSQL's own 22P02 into InvalidArgumentException satisfies a type
     * assertion, and does so invisibly to the query log because Laravel throws before logging.
     *
     * So: the value must never be carried into a credential query, and a refusal must happen.
     */
    $attempted = attemptedCredentialQueriesFor([$credentialId], fn () => app(CredentialLockManager::class)->acquire(
        DB::connection(),
        SubjectKey::forConfiguredUser(1),
        [$credentialId],
    ));

    expect($attempted)->toHaveCount(1);
    expect($attempted[0])->toStartWith('REFUSED: ');
})->with(nonCanonicalCredentialIds());

it('locks nothing when any one credential id in the list is bad', function (): void {
    /*
     * Measured: an implementation checking only the first id accepts ['1', '09']. And locking part
     * of a list before refusing the rest leaves locks held for a call that failed, so the whole
     * list must clear before anything is taken -- including the id that was fine.
     */
    $attempted = attemptedCredentialQueriesFor(['1', '09'], fn () => app(CredentialLockManager::class)->acquire(
        DB::connection(),
        SubjectKey::forConfiguredUser(1),
        ['1', '09'],
    ));

    expect($attempted)->toHaveCount(1);
    expect($attempted[0])->toStartWith('REFUSED: ');
});

it('accepts and locks every canonical credential id, including the portable maximum', function (): void {
    /*
     * The positive control, and the previous form proved nothing: it created no credential rows and
     * omitted the maximum, so mutants that rejected the maximum inside acquire(), or that omitted
     * every lockCredential() call, both passed. Real rows now exist and the maximum is among them.
     *
     * This asserts ACCEPTANCE of the domain, which is what #19 is about. That the lock itself
     * excludes a competing writer is asserted by the concurrency tests, not here.
     */
    $ids = ['1', '9', '1234567890', '9223372036854775807'];
    seedCredentials($ids);

    $attempted = attemptedCredentialQueriesFor($ids, function () use ($ids): void {
        DB::transaction(function () use ($ids): void {
            app(CredentialLockManager::class)->acquire(DB::connection(), SubjectKey::forConfiguredUser(1), $ids);
        });
    });

    // One lookup per id, no refusal: the ids were accepted and each was reached.
    expect($attempted)->toHaveCount(count($ids));

    foreach ($attempted as $query) {
        expect($query)->not->toStartWith('REFUSED: ');
    }
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

/** @param list<string> $ids */
function seedCredentials(array $ids): void
{
    DB::table('auth_credentials')->insert(array_map(static fn (string $id): array => [
        'id' => $id,
        'user_id' => 1,
        'type' => 'password',
        'secret' => 'irrelevant',
        'strength' => 'knowledge',
        'is_multi_factor' => 0,
        'user_verified' => 0,
        'phishing_resistant' => 0,
    ], $ids));
}

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
