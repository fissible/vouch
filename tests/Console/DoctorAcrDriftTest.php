<?php

declare(strict_types=1);

use Fissible\Vouch\Console\CommandExit;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Tests\Support\Assurance\CappingVocabulary;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * Issue #10 -- the drift diagnostic.
 *
 * The stored `acr` is a projection of what the bound vocabulary called the
 * evidence at write time, and it is never rewritten. That is correct, and it is
 * also invisible: after a host changes vocabulary every historical row
 * disagrees with a fresh derivation and nothing says so.
 *
 * This makes the disagreement OBSERVABLE without making it consequential. The
 * distinction is the design: a diagnostic that failed on drift would turn a
 * correct, intentional migration into a red check on every deployment, and an
 * operator who learns to ignore a red check has lost the signal for the case
 * that really is corruption.
 *
 * The report shape is asserted field by field rather than by string match. A
 * substring assertion over encoded JSON passes on a report that merely mentions
 * the table name somewhere, which is not what any of these tests mean.
 */

/** Write a session row with an arbitrary stored projection. */
function driftSession(int $userId, string $storedAcr, string $derives = 'aal2'): AuthSession
{
    $session = new AuthSession();
    $session->user_id = $userId;
    $session->session_binding = str_pad('drift-' . $userId . '-', 64, 'b');
    $session->amr = ['password'];
    $session->acr = $storedAcr;
    $session->assurance_proof = sessionProof($userId, $derives);
    $session->weakest_satisfied_at = now();
    $session->save();

    return $session;
}

/** Write a human token assurance row with an arbitrary stored projection. */
function driftToken(string $tokenKey, string $storedAcr, string $derives = 'aal2'): void
{
    DB::table('auth_token_assurances')->insert([
        'issuer_key' => 'sanctum',
        'token_key' => $tokenKey,
        'subject_key' => configuredUserProvider() . ':1',
        'tenant_id' => null,
        'actor_kind' => 'human',
        'acr' => $storedAcr,
        'assurance_proof' => json_encode(sessionProof(1, $derives), JSON_THROW_ON_ERROR),
        'weakest_satisfied_at' => now(),
        'created_at' => now(),
        'updated_at' => now(),
    ]);
}


/**
 * Every query this command issues against one table, in order.
 *
 * Deliberately NOT filtered to statements beginning with `select`: an unbounded
 * read phrased as a common table expression starts with `with`, and filtering it
 * out would let exactly the scan this test exists to forbid slip past.
 *
 * @return list<string>
 */
function driftReadsAgainst(string $table, callable $run): array
{
    $seen = [];

    DB::listen(static function (\Illuminate\Database\Events\QueryExecuted $query) use (&$seen, $table): void {
        $sql = strtolower(ltrim($query->sql));

        if (str_contains($sql, $table)) {
            $seen[] = $sql;
        }
    });

    $run();

    /*
     * No exemption, deliberately. An earlier draft excused any statement
     * containing `count(`, on the theory that an aggregate returns one row and
     * needs no bound. `select s.*, count(*) over () from auth_sessions s`
     * returns every row and would have been excused; so would an unbounded
     * outer fetch carrying a scalar count subquery. Classifying SQL by text is
     * not a rule that can be enforced, so there is no classification.
     *
     * The scan does not need an aggregate: its counts come from the rows it
     * inspects. So every statement it issues against these tables is bounded,
     * and this returns all of them.
     */
    return $seen;
}

/** @return array<string, mixed> */
function doctorReport(): array
{
    Artisan::call('vouch:doctor', ['--json' => true]);

    return jsonBody(Artisan::output());
}

/**
 * The drift section for one table, or fail loudly.
 *
 * @param  array<string, mixed>  $report
 * @return array<string, mixed>
 */
function driftFor(array $report, string $table): array
{
    $section = $report['acr_drift'] ?? null;

    if (! is_array($section) || ! is_array($section['tables'] ?? null)) {
        throw new RuntimeException('vouch:doctor reported no acr_drift section with a tables list.');
    }

    foreach ($section['tables'] as $row) {
        if (is_array($row) && ($row['table'] ?? null) === $table) {
            /** @var array<string, mixed> $row */
            return $row;
        }
    }

    throw new RuntimeException("vouch:doctor did not report on {$table}.");
}

/**
 * The drift table list, asserted to be exactly the two tables, once each.
 *
 * An omitted row and a zero row are different claims about a table, and only
 * one of them is true of an empty one. toMatchArray() on a single row cannot
 * catch a duplicate entry, a missing table, or a third invented one.
 *
 * @param  array<string, mixed>  $report
 * @return list<string>
 */
function driftTableNames(array $report): array
{
    $section = $report['acr_drift'] ?? null;

    if (! is_array($section) || ! is_array($section['tables'] ?? null)) {
        throw new RuntimeException('vouch:doctor reported no acr_drift section with a tables list.');
    }

    return array_map(
        static fn (mixed $row): string => is_array($row) ? stringValue($row['table'] ?? null) : '',
        array_values($section['tables']),
    );
}

/** @param array<string, mixed> $report */
function driftStatus(array $report): string
{
    $section = $report['acr_drift'] ?? null;

    return is_array($section) ? stringValue($section['status'] ?? null) : '';
}

it('reports no drift when the projection agrees with the bound vocabulary', function (): void {
    driftSession(1, 'aal2');
    driftToken('token-1', 'aal2');

    $report = doctorReport();

    expect(driftStatus($report))->toBe('pass')
        ->and(driftFor($report, 'auth_sessions'))->toBe(['table' => 'auth_sessions', 'checked' => 1, 'drifted' => 0, 'unreadable' => 0])
        ->and(driftFor($report, 'auth_token_assurances'))->toBe(['table' => 'auth_token_assurances', 'checked' => 1, 'drifted' => 0, 'unreadable' => 0]);
});

it('reports both tables exactly once, on an empty database', function (): void {
    /*
     * Nothing seeded. A report that omits a table it found nothing in is
     * indistinguishable from one that never looked, and an operator cannot tell
     * "clean" from "unchecked".
     */
    $report = doctorReport();

    expect(driftTableNames($report))->toBe(['auth_sessions', 'auth_token_assurances'])
        ->and(driftStatus($report))->toBe('pass')
        ->and(driftFor($report, 'auth_sessions'))->toBe(['table' => 'auth_sessions', 'checked' => 0, 'drifted' => 0, 'unreadable' => 0])
        ->and(driftFor($report, 'auth_token_assurances'))->toBe(['table' => 'auth_token_assurances', 'checked' => 0, 'drifted' => 0, 'unreadable' => 0]);
});

it('raises the status on token drift alone', function (): void {
    /*
     * Sessions clean, tokens drifted. A status computed from the sessions row
     * and then never revisited reports pass on a fleet whose every issued token
     * disagrees.
     */
    driftSession(1, 'aal1', 'aal1');
    driftToken('token-1', 'aal2');
    app()->instance(AssuranceVocabulary::class, new CappingVocabulary());

    $report = doctorReport();

    expect(driftFor($report, 'auth_sessions'))->toBe(['table' => 'auth_sessions', 'checked' => 1, 'drifted' => 0, 'unreadable' => 0])
        ->and(driftFor($report, 'auth_token_assurances'))->toBe(['table' => 'auth_token_assurances', 'checked' => 1, 'drifted' => 1, 'unreadable' => 0])
        ->and(driftStatus($report))->toBe('drift');
});

it('counts a row whose projection the current vocabulary would not produce', function (): void {
    /*
     * The row was named aal2 by whatever was bound when it was written. The
     * capping vocabulary now names those same factors aal1.
     */
    driftSession(1, 'aal2');
    app()->instance(AssuranceVocabulary::class, new CappingVocabulary());

    $report = doctorReport();

    expect(driftStatus($report))->toBe('drift')
        ->and(driftFor($report, 'auth_sessions'))->toBe(['table' => 'auth_sessions', 'checked' => 1, 'drifted' => 1, 'unreadable' => 0]);
});

it('counts drift on token records as well as sessions', function (): void {
    /*
     * Both tables carry the projection. A diagnostic covering only the one an
     * implementer happened to open first would report a clean fleet while every
     * issued token disagreed.
     */
    driftSession(1, 'aal2');
    driftToken('token-1', 'aal2');
    app()->instance(AssuranceVocabulary::class, new CappingVocabulary());

    $report = doctorReport();

    expect(driftFor($report, 'auth_sessions'))->toBe(['table' => 'auth_sessions', 'checked' => 1, 'drifted' => 1, 'unreadable' => 0])
        ->and(driftFor($report, 'auth_token_assurances'))->toBe(['table' => 'auth_token_assurances', 'checked' => 1, 'drifted' => 1, 'unreadable' => 0]);
});

it('does not count a machine token, which has no projection to drift from', function (): void {
    /*
     * A machine record stores a null acr and a null proof by contract. Counting
     * it as drift -- or as unreadable -- would report a permanent fault on
     * every correctly issued machine token.
     */
    DB::table('auth_token_assurances')->insert([
        'issuer_key' => 'sanctum',
        'token_key' => 'machine-1',
        'subject_key' => configuredUserProvider() . ':1',
        'tenant_id' => null,
        'actor_kind' => 'machine',
        'acr' => null,
        'assurance_proof' => null,
        'weakest_satisfied_at' => null,
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    app()->instance(AssuranceVocabulary::class, new CappingVocabulary());

    expect(driftFor(doctorReport(), 'auth_token_assurances'))
        ->toBe(['table' => 'auth_token_assurances', 'checked' => 0, 'drifted' => 0, 'unreadable' => 0]);
});

it('does not fail the command on drift', function (): void {
    /*
     * The load-bearing assertion of this file. Drift is configuration or
     * version movement, not a missing prerequisite: it must not increment
     * `missing` and must not change the exit code.
     */
    /*
     * Measured against this environment's own baseline rather than against
     * zero. An earlier draft asserted missing === 0 and a Success exit, which
     * says nothing about drift: the test environment leaves OtpDelivery and
     * DeliveryEconomics unbound, so `missing` is already non-zero and the
     * command already fails for reasons that predate this feature.
     *
     * What the contract actually promises is that drift CHANGES neither. So
     * both are captured with a clean fleet, then re-measured with a drifted
     * one.
     */
    driftSession(1, 'aal1', 'aal1');

    $clean = doctorReport();
    $cleanExit = Artisan::call('vouch:doctor');

    expect(driftStatus($clean))->toBe('pass');

    driftSession(2, 'aal2');
    app()->instance(AssuranceVocabulary::class, new CappingVocabulary());

    $drifted = doctorReport();

    expect(driftStatus($drifted))->toBe('drift')
        ->and($drifted['missing'])->toBe($clean['missing'])
        ->and(Artisan::call('vouch:doctor'))->toBe($cleanExit);
});

it('shows drift to an operator who did not ask for json', function (): void {
    /*
     * A diagnostic nobody sees is not a diagnostic. The default rendering must
     * name the drifted table, not bury it behind a flag.
     */
    driftSession(1, 'aal2');
    app()->instance(AssuranceVocabulary::class, new CappingVocabulary());

    driftToken('token-1', 'aal2');

    Artisan::call('vouch:doctor');
    $output = Artisan::output();

    /*
     * The table name alone is not the diagnostic. The counts are what an
     * operator acts on, so they have to survive the rendering -- for BOTH
     * tables, since a renderer that formatted the first row and printed the
     * second as a bare name would satisfy a name-only assertion.
     */
    expect(preg_match('/auth_sessions\D+1\D+1\D+0/', $output))->toBe(1)
        ->and(preg_match('/auth_token_assurances\D+1\D+1\D+0/', $output))->toBe(1);
});

it('names an unreadable row in the default rendering', function (): void {
    /*
     * The addendum requires unreadable rows to be visible in text even though
     * they do not raise the status. A renderer showing only drift would hide
     * corruption behind the very rule that keeps intentional migrations quiet.
     */
    $session = driftSession(1, 'aal2');
    DB::table('auth_sessions')->where('id', $session->id)->update(['assurance_proof' => '{"nope":true}']);

    Artisan::call('vouch:doctor');

    expect(preg_match('/auth_sessions\D+1\D+0\D+1/', Artisan::output()))->toBe(1);
});

it('separates an unreadable proof from a drifted one', function (): void {
    /*
     * Different causes, different remedies. A proof that will not deserialize
     * is corruption or a schema change; a projection that disagrees is a
     * vocabulary decision. Counting them together hides the first inside the
     * noise of an intentional migration.
     */
    $session = driftSession(1, 'aal2');
    DB::table('auth_sessions')->where('id', $session->id)->update(['assurance_proof' => '{"nope":true}']);

    $report = doctorReport();

    expect(driftFor($report, 'auth_sessions'))
        ->toBe(['table' => 'auth_sessions', 'checked' => 1, 'drifted' => 0, 'unreadable' => 1])
        // Unreadable is corruption, drift is a vocabulary decision. Only the
        // second one raises the status; conflating them buries the first in the
        // noise of an intentional migration.
        ->and(driftStatus($report))->toBe('pass');
});

it('iterates in batches rather than reading either table at once', function (): void {
    /*
     * An earlier draft seeded 250 rows and asserted "more than one select".
     * That established nothing: with the batch size unspecified, requiring two
     * selects over 250 rows silently pins the batch below 250 while claiming
     * not to, and correct totals are equally produced by one unbounded query.
     *
     * So the size is configuration -- vouch.doctor.drift_batch -- and the
     * fixture exceeds a deliberately small one. 60 rows over a batch of 25 must
     * take at least three passes, a number that follows from the configured
     * size rather than from one chosen to make the assertion true.
     *
     * Both tables, because proving it of the first says nothing about the
     * second, and an implementation that iterated sessions politely while
     * loading every token record at once is the likelier of the two mistakes.
     */
    config(['vouch.doctor.drift_batch' => 25]);

    for ($userId = 1; $userId <= 60; $userId++) {
        driftSession($userId, 'aal2');
        driftToken('token-' . $userId, 'aal2');
    }

    app()->instance(AssuranceVocabulary::class, new CappingVocabulary());

    $sessionReads = [];
    $tokenReads = driftReadsAgainst('auth_token_assurances', function () use (&$sessionReads): void {
        $sessionReads = driftReadsAgainst('auth_sessions', static function (): void {
            doctorReport();
        });
    });

    foreach (['auth_sessions' => $sessionReads, 'auth_token_assurances' => $tokenReads] as $table => $reads) {
        // ceil(60 / 25) = 3 passes at minimum.
        expect(count($reads))->toBeGreaterThanOrEqual(3, "{$table} was not read in batches");

        /*
         * Every statement bounded. This is the assertion aimed at the
         * batch-politely-then-sweep-the-rest implementation, at the CTE
         * phrasing of the same thing, and at the window function that returns
         * every row while reading as an aggregate. None carries a limit.
         */
        expect(array_filter($reads, static fn (string $sql): bool => ! str_contains($sql, 'limit')))
            ->toBe([], "{$table} had an unbounded row fetch");
    }
});

it('counts a human row with no projection as unreadable, not as clean', function (): void {
    /*
     * A readable proof beside a null acr is corruption: the writers always
     * store both. It cannot be compared, so it is not drift -- but dropping it
     * from every count would make it invisible, which is the one outcome the
     * classification exists to prevent.
     */
    $session = driftSession(1, 'aal2');
    DB::table('auth_sessions')->where('id', $session->id)->update(['acr' => null]);

    expect(driftFor(doctorReport(), 'auth_sessions'))
        ->toBe(['table' => 'auth_sessions', 'checked' => 1, 'drifted' => 0, 'unreadable' => 1]);
});

it('does not let the machine exemption swallow a malformed machine row', function (): void {
    /*
     * A machine record in its contracted shape is excluded. A machine record
     * carrying a human proof is not in that shape, and treating the actor kind
     * alone as the exemption would hide it permanently.
     */
    DB::table('auth_token_assurances')->insert([
        'issuer_key' => 'sanctum',
        'token_key' => 'machine-malformed',
        'subject_key' => configuredUserProvider() . ':1',
        'tenant_id' => null,
        'actor_kind' => 'machine',
        'acr' => 'aal2',
        'assurance_proof' => json_encode(sessionProof(1, 'aal2'), JSON_THROW_ON_ERROR),
        'weakest_satisfied_at' => now(),
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    expect(driftFor(doctorReport(), 'auth_token_assurances'))
        ->toBe(['table' => 'auth_token_assurances', 'checked' => 1, 'drifted' => 0, 'unreadable' => 1]);
});

it('excludes a legacy session that never carried a proof', function (): void {
    /*
     * The pre-2.4 state SessionEvidence already reports as LegacyNoProof. It is
     * a known-good row, not corruption, and counting it would put a permanent
     * non-zero number in front of every operator who upgraded.
     *
     * The acr is deliberately RETAINED here, because that is the realistic
     * legacy shape: rows written before 2.4 stored a level and no proof. The
     * exclusion keys on the absent proof alone, so an implementation keying on
     * "both null" would report every upgraded fleet as corrupt.
     */
    $session = driftSession(1, 'aal2');
    DB::table('auth_sessions')->where('id', $session->id)->update(['assurance_proof' => null]);

    expect(driftFor(doctorReport(), 'auth_sessions'))
        ->toBe(['table' => 'auth_sessions', 'checked' => 0, 'drifted' => 0, 'unreadable' => 0]);
});

it('excludes a legacy session that carries neither a proof nor a level', function (): void {
    $session = driftSession(1, 'aal2');
    DB::table('auth_sessions')->where('id', $session->id)
        ->update(['assurance_proof' => null, 'acr' => null]);

    expect(driftFor(doctorReport(), 'auth_sessions'))
        ->toBe(['table' => 'auth_sessions', 'checked' => 0, 'drifted' => 0, 'unreadable' => 0]);
});

it('counts a token row with an unrecognised actor kind as unreadable', function (): void {
    /*
     * actor_kind is an unconstrained string column. An unknown value must not be
     * compared as though it were human, nor excluded as though it were machine --
     * either way a corrupt row reads as clean. TokenAssuranceRecord::read()
     * already makes this judgement, returning ProofMalformed on an unparseable
     * actor before it examines anything else.
     */
    driftToken('token-1', 'aal2');
    DB::table('auth_token_assurances')->where('token_key', 'token-1')
        ->update(['actor_kind' => 'other']);

    expect(driftFor(doctorReport(), 'auth_token_assurances'))
        ->toBe(['table' => 'auth_token_assurances', 'checked' => 1, 'drifted' => 0, 'unreadable' => 1]);
});

it('counts a human token row with no proof as unreadable', function (): void {
    /*
     * The mirror of the machine exemption, and it does NOT get the legacy
     * treatment sessions do. TokenAssuranceRecord always writes a proof for a
     * human record, so its absence is corruption rather than an older shape --
     * and there is no pre-2.4 token row to be lenient about, because the table
     * had no consumer before 2.4.
     */
    driftToken('token-1', 'aal2');
    DB::table('auth_token_assurances')->where('token_key', 'token-1')
        ->update(['assurance_proof' => null]);

    expect(driftFor(doctorReport(), 'auth_token_assurances'))
        ->toBe(['table' => 'auth_token_assurances', 'checked' => 1, 'drifted' => 0, 'unreadable' => 1]);
});
