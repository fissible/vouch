<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 2 — the token assurance schema, asserted as CONSTRAINTS.
 *
 * Column-existence checks are close to worthless here: they pass for a
 * migration with the right names and none of the guarantees. A table that
 * stored token_key numerically, or let two rows describe one token, or scoped
 * credential mappings across issuers, would satisfy every hasColumn() call and
 * still be an authorization hazard.
 *
 * Cross-engine on purpose. Composite keys, JSON columns and string-vs-integer
 * identity are exactly where SQLite, MySQL and PostgreSQL diverge, and this
 * table sits on an authorization path.
 */
final class TokenAssuranceSchemaTest extends TestCase
{
    use DatabaseMigrations;
    use UsesSanctumSchema;

    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [SanctumServiceProvider::class, VouchServiceProvider::class];
    }

    /** @param array<string, mixed> $overrides */
    private function row(array $overrides = []): array
    {
        return array_merge([
            'issuer_key' => 'sanctum',
            'token_key' => '42',
            'subject_key' => 'App\\Models\\User:7',
            'tenant_id' => null,
            'actor_kind' => 'human',
            'acr' => 'aal2',
            'assurance_proof' => json_encode(['subject' => 'App\\Models\\User:7', 'tenant_id' => null, 'factors' => []]),
            'weakest_satisfied_at' => '2026-08-13 10:00:00',
            'created_at' => now(),
            'updated_at' => now(),
        ], $overrides);
    }

    #[Test]
    public function the_old_single_token_id_shape_is_gone(): void
    {
        /*
         * token_id stops being unique the moment the issuer is pluggable: two
         * drivers can each mint id 42, and one token's record would then
         * validate the other. The column must be REMOVED, not merely unused —
         * a leftover nullable column is a place for a future writer to land.
         */
        self::assertFalse(Schema::hasColumn('auth_token_assurances', 'token_id'));
        self::assertTrue(Schema::hasColumn('auth_token_assurances', 'issuer_key'));
        self::assertTrue(Schema::hasColumn('auth_token_assurances', 'token_key'));
    }

    #[Test]
    public function one_token_has_at_most_one_assurance_record(): void
    {
        // Two records for one token would let a reader pick whichever assurance
        // suited it, which is not a weaker guarantee but no guarantee at all.
        DB::table('auth_token_assurances')->insert($this->row());

        $this->expectException(QueryException::class);

        DB::table('auth_token_assurances')->insert($this->row(['subject_key' => 'App\\Models\\User:8']));
    }

    #[Test]
    public function two_issuers_may_mint_the_same_token_key(): void
    {
        // The other half of the composite key. If this throws, the migration
        // put the uniqueness on token_key alone and a second driver can never
        // record anything.
        DB::table('auth_token_assurances')->insert($this->row(['issuer_key' => 'sanctum']));
        DB::table('auth_token_assurances')->insert($this->row(['issuer_key' => 'passport']));

        self::assertSame(2, DB::table('auth_token_assurances')->count());
    }

    #[Test]
    public function the_token_key_is_string_identity_not_numeric(): void
    {
        /*
         * '42' and '042' are different tokens. Stored in an integer column they
         * collide, and the second insert either fails as a duplicate or — worse
         * — silently validates the first token's assurance for the second.
         *
         * The read-back is what proves it: a numeric column returns 42 for
         * both, so asserting the insert succeeded is not enough.
         */
        DB::table('auth_token_assurances')->insert($this->row(['token_key' => '42']));
        DB::table('auth_token_assurances')->insert($this->row(['token_key' => '042']));

        $keys = DB::table('auth_token_assurances')->orderBy('id')->pluck('token_key')->all();

        self::assertSame(['42', '042'], array_map(static fn (mixed $k): string => (string) $k, $keys));
    }

    #[Test]
    public function the_recency_anchor_is_nullable_because_machine_records_have_none(): void
    {
        /*
         * A null anchor is unanswerable for a max_age requirement — read as "no
         * limit" it fails open, read as "infinitely old" it locks out — so the
         * obvious move is NOT NULL. That is wrong here, and the contract said
         * so in two places at once until this was caught.
         *
         * A machine token carries no authentication evidence, so it has no
         * instant to record, and forcing the column non-null would make every
         * machine record store a fabricated timestamp — a fiction a later
         * recency check would happily read.
         *
         * The invariant is therefore actor-scoped and lives in the adapter, not
         * the column: a HUMAN record always has an anchor because its proof is
         * non-empty, a machine record has none, and a human row found without
         * one is refused at the read boundary. Machines never reach a recency
         * comparison anyway — MachineActor refuses first.
         */
        DB::table('auth_token_assurances')->insert($this->row([
            'token_key' => 'svc-1',
            'actor_kind' => 'machine',
            'weakest_satisfied_at' => null,
        ]));

        self::assertNull(DB::table('auth_token_assurances')->where('token_key', 'svc-1')->value('weakest_satisfied_at'));
    }

    #[Test]
    public function a_null_tenant_persists_as_null_rather_than_an_empty_string(): void
    {
        // Global and empty-string tenants are different claims, and the
        // comparator refuses a cross-tenant read. A column coercing null to ''
        // would make every global token look tenant-scoped to nothing.
        DB::table('auth_token_assurances')->insert($this->row(['tenant_id' => null]));

        self::assertNull(DB::table('auth_token_assurances')->value('tenant_id'));
    }

    #[Test]
    public function two_issuers_may_map_the_same_credential_to_the_same_token_key(): void
    {
        /*
         * The schema half of issuer scoping: the uniqueness must be on the
         * TRIPLE, not on (token_key, credential_id). If this throws, one
         * issuer's mapping blocks another's and the second driver can never
         * record.
         *
         * An earlier draft "proved" scoping by issuing a query with the issuer
         * predicate already in it — which demonstrates the test's own WHERE
         * clause and nothing about the schema. Whether a revocation sweep
         * actually scopes its reads is a property of the sweep, and belongs to
         * Task 5 where the sweep exists.
         */
        DB::table('auth_token_credentials')->insert([
            ['issuer_key' => 'sanctum', 'token_key' => '42', 'credential_id' => '9'],
            ['issuer_key' => 'passport', 'token_key' => '42', 'credential_id' => '9'],
        ]);

        self::assertSame(2, DB::table('auth_token_credentials')->count());
    }

    #[Test]
    #[DataProvider('emptyIdentityHalves')]
    public function the_assurance_record_rejects_an_empty_identity_half(string $column, mixed $value): void
    {
        /*
         * An empty identity half is not a token. Permitted, it creates a row
         * that every composite lookup misses and no revocation sweep can find,
         * which reads as "this token has no assurance" forever.
         *
         * BOTH halves and BOTH empties. An earlier draft tested only a null
         * token_key, which left three of the four cases unasserted — and an
         * ordinary non-null string column happily accepts '', so the null half
         * alone proves very little.
         */
        $this->expectException(QueryException::class);

        DB::table('auth_token_assurances')->insert($this->row([$column => $value]));
    }

    /** @return array<string, array{string, mixed}> */
    public static function emptyIdentityHalves(): array
    {
        return [
            'null issuer' => ['issuer_key', null],
            'null token' => ['token_key', null],
            'empty issuer' => ['issuer_key', ''],
            'empty token' => ['token_key', ''],
        ];
    }

    #[Test]
    public function one_credential_maps_to_a_token_at_most_once(): void
    {
        // A duplicate mapping row makes a revocation sweep report the wrong
        // count and, if the sweep is ever made idempotent by count, hide a
        // failure to delete.
        DB::table('auth_token_credentials')->insert([
            'issuer_key' => 'sanctum', 'token_key' => '42', 'credential_id' => '9',
        ]);

        $this->expectException(QueryException::class);

        DB::table('auth_token_credentials')->insert([
            'issuer_key' => 'sanctum', 'token_key' => '42', 'credential_id' => '9',
        ]);
    }

    #[Test]
    public function the_credential_id_is_string_identity_too(): void
    {
        // Same hazard as token_key, on the table that decides revocation reach.
        DB::table('auth_token_credentials')->insert([
            ['issuer_key' => 'sanctum', 'token_key' => '42', 'credential_id' => '9'],
            ['issuer_key' => 'sanctum', 'token_key' => '42', 'credential_id' => '09'],
        ]);

        $ids = DB::table('auth_token_credentials')->orderBy('id')->pluck('credential_id')->all();

        self::assertSame(['9', '09'], array_map(static fn (mixed $i): string => (string) $i, $ids));
    }

    #[Test]
    public function it_declares_the_indexes_task_5_revocation_depends_on(): void
    {
        /*
         * Named now because adding an index later means another migration on a
         * live authorization table, and because a missing one is invisible: the
         * queries still return the right answer, just by scanning.
         *
         * Each is tied to a query Task 5 is already specified to run:
         *  - credential -> tokens, on every credential disable/replace/revoke.
         *    Unindexed this scans the whole revocation path, which is the one
         *    place latency turns into a security problem.
         *  - subject + actor kind, for the password-change sweep of a subject's
         *    HUMAN tokens; machine tokens are deliberately excluded from it.
         *  - the recency anchor, which the design doc specified as indexed for
         *    audit and reporting reads.
         */
        $expected = [
            'auth_token_assurances' => [
                'auth_token_assurance_identity_unique' => ['issuer_key', 'token_key'],
                'auth_token_assurance_subject_index' => ['subject_key', 'actor_kind'],
                'auth_token_assurance_recency_index' => ['weakest_satisfied_at'],
            ],
            'auth_token_credentials' => [
                'auth_token_credential_unique' => ['issuer_key', 'token_key', 'credential_id'],
                'auth_token_credential_lookup_index' => ['credential_id'],
            ],
        ];

        foreach ($expected as $table => $indexes) {
            $actual = collect(Schema::getIndexes($table))->keyBy('name');

            foreach ($indexes as $name => $columns) {
                self::assertTrue($actual->has($name), "Missing index {$name} on {$table}.");
                self::assertSame($columns, $actual->get($name)['columns'] ?? null);
            }
        }
    }

    #[Test]
    public function it_carries_a_derived_level_projection_for_hosts_to_index(): void
    {
        /*
         * PARITY WITH auth_sessions, and a projection under exactly the same
         * rule: never an authorization input, in either direction. Without it a
         * host listing "which of my tokens are aal2" must deserialize every
         * proof, which pushes them toward reading the payload themselves — and
         * a host reading the payload is a host one step from authorizing on it.
         *
         * Nullable, because a machine token has no human level to project.
         */
        DB::table('auth_token_assurances')->insert($this->row(['acr' => 'aal2']));
        DB::table('auth_token_assurances')->insert($this->row([
            'token_key' => 'svc-1', 'actor_kind' => 'machine', 'acr' => null, 'weakest_satisfied_at' => null,
        ]));

        self::assertSame('aal2', DB::table('auth_token_assurances')->where('token_key', '42')->value('acr'));
        self::assertNull(DB::table('auth_token_assurances')->where('token_key', 'svc-1')->value('acr'));
    }
}
