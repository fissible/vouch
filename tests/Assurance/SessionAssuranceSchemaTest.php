<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

/*
 * 2.4 Task 2a — the resulting schema.
 *
 * Asserting that a column exists is close to worthless: it passes for a
 * migration with the right names and none of the constraints. These assert
 * persisted values and the nullability that upgrade depends on.
 *
 * The upgrade ITSELF is not tested here. Running a migration object's down()
 * and up() underneath RefreshDatabase bypasses migration bookkeeping entirely,
 * and MySQL commits DDL implicitly, which breaks the surrounding transaction
 * rather than exercising a host's real forward path. That lives in
 * SessionAssuranceUpgradeTest, which runs the migrator outside a transaction.
 */

it('replaces the derived-summary column with the immutable proof', function (): void {
    /*
     * assurance_facts held a DERIVED summary and never had a writer. Leaving it
     * beside the proof would leave a cache of conclusions next to the evidence
     * they came from, which is the shape that invites authorizing from the
     * summary -- the exact drift this task removes. It is dropped, not kept
     * "for compatibility": nothing ever wrote to it.
     */
    expect(Schema::hasColumn('auth_sessions', 'assurance_proof'))->toBeTrue()
        ->and(Schema::hasColumn('auth_sessions', 'assurance_facts'))->toBeFalse();
});

it('names the recency column for the semantics it actually has', function (): void {
    // last_factor_at read as "most recent factor" while its migration comment
    // said "oldest satisfied factor". A name that contradicts the value is a
    // bug waiting for the next reader.
    expect(Schema::hasColumn('auth_sessions', 'weakest_satisfied_at'))->toBeTrue()
        ->and(Schema::hasColumn('auth_sessions', 'last_factor_at'))->toBeFalse();
});

it('leaves the proof nullable, because legacy rows have none', function (): void {
    /*
     * A NOT NULL proof column would make the upgrade itself fail on any host
     * with a live session, and there is no backfill value that would be
     * honest. Nullable is the deliberate choice; SessionEvidence refusing a
     * null proof is what keeps it safe.
     */
    DB::table('auth_sessions')->insert([
        'session_binding' => str_repeat('c', 64),
        'user_id' => 7,
        'amr' => json_encode(['password']),
        'acr' => 'aal1',
        'assurance_proof' => null,
        'weakest_satisfied_at' => null,
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    expect(DB::table('auth_sessions')->where('user_id', 7)->count())->toBe(1);
});

it('persists a timestamp that survives a non-UTC process timezone', function (): void {
    /*
     * Timestamp columns carry no offset on any of the three engines, so the
     * instant is only preserved if the application writes and reads in a fixed
     * zone. Written under one default timezone and read under another, this
     * fails the moment something resolves the value locally.
     */
    $original = date_default_timezone_get();

    try {
        date_default_timezone_set('America/Los_Angeles');
        DB::table('auth_sessions')->insert([
            'session_binding' => str_repeat('d', 64),
            'user_id' => 8,
            'amr' => json_encode(['password']),
            'acr' => 'aal1',
            'assurance_proof' => null,
            'weakest_satisfied_at' => '2026-08-29 10:00:00',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        date_default_timezone_set('Asia/Tokyo');
        $read = DB::table('auth_sessions')->where('user_id', 8)->value('weakest_satisfied_at');

        expect(substr(stringValue($read), 0, 19))->toBe('2026-08-29 10:00:00');
    } finally {
        date_default_timezone_set($original);
    }
});

it('keeps one live row per binding after the change', function (): void {
    // The unique constraint predates 2a, and a migration that recreates the
    // table -- which the SQLite path may do to rename a column -- is exactly
    // how a constraint gets silently dropped.
    DB::table('auth_sessions')->insert([
        'session_binding' => str_repeat('e', 64),
        'user_id' => 9,
        'amr' => json_encode(['password']),
        'acr' => 'aal1',
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    expect(fn () => DB::table('auth_sessions')->insert([
        'session_binding' => str_repeat('e', 64),
        'user_id' => 10,
        'amr' => json_encode(['password']),
        'acr' => 'aal1',
        'created_at' => now(),
        'updated_at' => now(),
    ]))->toThrow(Illuminate\Database\QueryException::class);
});
