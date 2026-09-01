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
    driftSession(1, 'aal2');
    app()->instance(AssuranceVocabulary::class, new CappingVocabulary());

    $report = doctorReport();

    expect(driftStatus($report))->toBe('drift')
        ->and($report['missing'])->toBe(0)
        ->and(Artisan::call('vouch:doctor'))->toBe(CommandExit::Success->value);
});

it('shows drift to an operator who did not ask for json', function (): void {
    /*
     * A diagnostic nobody sees is not a diagnostic. The default rendering must
     * name the drifted table, not bury it behind a flag.
     */
    driftSession(1, 'aal2');
    app()->instance(AssuranceVocabulary::class, new CappingVocabulary());

    Artisan::call('vouch:doctor');
    $output = Artisan::output();

    // The table name alone is not the diagnostic. The counts are what an
    // operator acts on, so they have to survive the rendering.
    expect($output)->toContain('auth_sessions')
        ->and($output)->toContain('auth_token_assurances')
        ->and(preg_match('/auth_sessions\D+1\D+1\D+0/', $output))->toBe(1);
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

it('counts every row when there are more than one batch of them', function (): void {
    /*
     * The sweep reads bounded batches rather than one unbounded query, so the
     * counts must survive a batch boundary. Deliberately asserts the TOTAL and
     * not the batch size: the boundary is an implementation choice, and pinning
     * it here would freeze it.
     */
    for ($userId = 1; $userId <= 250; $userId++) {
        driftSession($userId, 'aal2');
    }

    app()->instance(AssuranceVocabulary::class, new CappingVocabulary());

    $selects = [];
    DB::listen(static function (\Illuminate\Database\Events\QueryExecuted $query) use (&$selects): void {
        if (str_contains($query->sql, 'auth_sessions') && str_starts_with(strtolower(ltrim($query->sql)), 'select')) {
            $selects[] = $query->sql;
        }
    });

    $report = doctorReport();

    expect(driftFor($report, 'auth_sessions'))
        ->toBe(['table' => 'auth_sessions', 'checked' => 250, 'drifted' => 250, 'unreadable' => 0]);

    /*
     * Correct counts alone do not establish bounded reads -- a single unbounded
     * query over 250 rows produces exactly the same totals. So the reads
     * themselves are inspected: more than one select, and every one of them
     * limited.
     *
     * The batch SIZE is deliberately not pinned. It is an operational choice,
     * and freezing it here would make tuning it a test change.
     */
    expect(count($selects))->toBeGreaterThan(1);
    expect(array_filter($selects, static fn (string $sql): bool => ! str_contains(strtolower($sql), 'limit')))->toBe([]);
});
