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
    public function the_recency_anchor_cannot_be_null(): void
    {
        /*
         * A null anchor is unanswerable for a max_age requirement: treated as
         * "no limit" it fails open for every recorded token, and treated as
         * "infinitely old" it locks out every one. Neither is a policy, so the
         * column must refuse the case outright.
         */
        $this->expectException(QueryException::class);

        DB::table('auth_token_assurances')->insert($this->row(['weakest_satisfied_at' => null]));
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
    public function credential_mappings_are_scoped_to_their_issuer(): void
    {
        /*
         * The mapping table is read on a revocation path: "which tokens does
         * this credential authorize?" Scoped by credential alone, disabling a
         * credential would revoke a DIFFERENT issuer's token that happens to
         * share a token key — and, worse, would miss nothing while appearing to
         * work.
         */
        DB::table('auth_token_credentials')->insert([
            ['issuer_key' => 'sanctum', 'token_key' => '42', 'credential_id' => '9'],
            ['issuer_key' => 'passport', 'token_key' => '42', 'credential_id' => '9'],
        ]);

        $scoped = DB::table('auth_token_credentials')
            ->where('issuer_key', 'sanctum')->where('credential_id', '9')->get();

        self::assertCount(1, $scoped);
        self::assertSame('sanctum', $scoped->first()?->issuer_key);
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
}
