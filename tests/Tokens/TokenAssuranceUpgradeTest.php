<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 2 — the upgrade off the old token_id shape.
 *
 * Addendum §4 chose drop-and-recreate over a migration, on the grounds that
 * `auth_token_assurances` has no runtime authorization consumer — it is a model
 * and fixture surface only — and §6.5 point 4 already forbids adopting
 * pre-existing tokens, which are reissued rather than backfilled because
 * backfilling asserts a fact nobody witnessed.
 *
 * That reasoning is recorded rather than merely believed: the first test below
 * holds the "no runtime consumer" claim to the actual source tree, because it
 * is the entire justification for discarding data, and it stops being true the
 * moment someone adds a reader.
 */
final class TokenAssuranceUpgradeTest extends TestCase
{
    use DatabaseMigrations;
    use UsesSanctumSchema;

    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [SanctumServiceProvider::class, VouchServiceProvider::class];
    }

    #[Test]
    public function no_code_outside_the_canonical_adapter_reads_the_table_directly(): void
    {
        /*
         * WHAT THIS PROVES, precisely: no file outside the model and the
         * canonical record adapter touches this table. It does NOT prove "no
         * runtime authorization consumer", which is what an earlier version of
         * this test claimed while exempting TokenAssuranceRecord — the very
         * reader that authorization goes through. A scan cannot support that
         * stronger claim while excluding the reader it would have to examine.
         *
         * The narrower property is still worth holding: it keeps table access
         * funnelled through one adapter, so the read-boundary refusals cannot be
         * bypassed by a second reader that forgets them.
         *
         * Scoped to Vouch-owned code, deliberately and no wider: a host's raw
         * SQL or reporting job is invisible here, which is why the upgrade note
         * tells hosts about the drop rather than relying on this.
         */
        $root = (string) realpath(__DIR__ . '/../../src');
        $offenders = [];

        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root));

        foreach ($files as $file) {
            if (! $file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }

            $path = (string) $file->getRealPath();
            $relative = str_replace($root . '/', '', $path);

            /*
             * Whitelist the two files that legitimately own this table, and
             * NOTHING wider. An earlier draft excluded all of src/Tokens/ —
             * which is exactly where the new adapter and any future
             * authorization reader live, so a Tokens/TokenGate reading the
             * table directly would have passed the assertion designed to catch
             * it.
             */
            if (in_array($relative, ['Models/AuthTokenAssurance.php', 'Tokens/TokenAssuranceRecord.php'], true)) {
                continue;
            }

            /*
             * CODE tokens only. A raw string scan matches prose: OtpFactor's
             * docblock mentions auth_token_assurances to explain why it
             * preserves a credential id, and counting that as a consumer would
             * make this assertion fire on a comment. Its known limit, so a
             * reader calibrates trust: a table name assembled at runtime is
             * invisible to it, which is a deliberate circumvention rather than
             * an accident.
             */
            foreach (token_get_all((string) file_get_contents($path)) as $token) {
                if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT, T_INLINE_HTML], true)) {
                    continue;
                }

                $text = is_array($token) ? $token[1] : $token;

                if (str_contains($text, 'AuthTokenAssurance') || str_contains($text, 'auth_token_assurances')) {
                    $offenders[] = $relative;
                    break;
                }
            }
        }

        self::assertSame([], $offenders, 'A second direct reader appeared; table access must stay funnelled through TokenAssuranceRecord.');
    }

    #[Test]
    public function an_installed_host_on_the_old_shape_is_carried_forward(): void
    {
        /*
         * THE upgrade, which the rest of this file does not test.
         * DatabaseMigrations starts from an empty database, so editing the
         * original create migration in place satisfies every other assertion
         * here while an installed 0.1.1 host keeps its token_id table forever
         * and never runs anything. The replacement must therefore be a NEW
         * migration, and it must run over the historic shape.
         *
         * Built by hand rather than by rolling back, because the historic shape
         * is what shipped — reconstructing it from the current migration would
         * test today's code against itself.
         */
        Schema::dropIfExists('auth_token_assurances');
        Schema::dropIfExists('auth_token_credentials');

        Schema::create('auth_token_assurances', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('token_id')->unique();
            $table->string('acr', 64);
            $table->json('amr');
            $table->json('credential_ids');
            $table->string('issuing_session_id', 255)->index();
            $table->timestamp('issued_at');
            $table->timestamps();
        });

        DB::table('auth_token_assurances')->insert([
            'token_id' => 42,
            'acr' => 'aal2',
            'amr' => json_encode(['password', 'totp']),
            'credential_ids' => json_encode([9]),
            'issuing_session_id' => 'sess-1',
            'issued_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $migration = self::replacementMigration();
        $migration->up();

        // Recreated, not altered: the old row is GONE rather than half-migrated
        // into a shape whose proof column nobody ever wrote.
        self::assertFalse(Schema::hasColumn('auth_token_assurances', 'token_id'));
        self::assertTrue(Schema::hasColumn('auth_token_assurances', 'issuer_key'));
        self::assertSame(0, DB::table('auth_token_assurances')->count());
        self::assertTrue(Schema::hasTable('auth_token_credentials'));
    }

    #[Test]
    public function the_replacement_ships_as_a_new_migration_not_an_edit_to_history(): void
    {
        /*
         * The distinction an installed host depends on. Editing
         * 2026_08_12_000009_create_auth_token_assurances.php changes nothing for
         * anyone who already migrated; only a new file runs.
         */
        $original = glob(self::migrationsDirectory() . '/*create_auth_token_assurances*.php');
        $replacement = glob(self::migrationsDirectory() . '/*token_assurance_identity*.php');

        self::assertNotSame([], $original === false ? [] : $original, 'The historic migration must remain.');
        self::assertCount(1, $replacement === false ? [] : $replacement);
    }

    private static function migrationsDirectory(): string
    {
        $dir = realpath(__DIR__ . '/../../database/migrations');

        if ($dir === false) {
            throw new \RuntimeException('The migrations directory does not exist.');
        }

        return $dir;
    }

    private static function replacementMigration(): \Illuminate\Database\Migrations\Migration
    {
        $matches = glob(self::migrationsDirectory() . '/*token_assurance_identity*.php');
        $matches = $matches === false ? [] : $matches;

        self::assertCount(1, $matches);

        /** @var \Illuminate\Database\Migrations\Migration $migration */
        $migration = require $matches[0];

        return $migration;
    }

    #[Test]
    public function the_replacement_table_starts_empty_rather_than_backfilled(): void
    {
        /*
         * §6.5 point 4. A pre-existing token has no recorded proof, and deriving
         * one from its old acr/amr columns would manufacture factors that were
         * never presented at timestamps that were never observed. Tokens are
         * reissued; nothing is adopted.
         */
        self::assertTrue(Schema::hasTable('auth_token_assurances'));
        self::assertSame(0, DB::table('auth_token_assurances')->count());
        self::assertTrue(Schema::hasTable('auth_token_credentials'));
        self::assertSame(0, DB::table('auth_token_credentials')->count());
    }

    #[Test]
    public function the_old_columns_are_gone_rather_than_left_nullable(): void
    {
        /*
         * A leftover amr/credential_ids column is not inert: it is a cached
         * assurance summary sitting beside the proof that replaced it, which is
         * precisely the shape Task 2a spent its existence removing from
         * auth_sessions. Nothing should be able to authorize from it again.
         *
         * `acr` is DELIBERATELY ABSENT from this list, and its absence is the
         * point rather than an oversight. The column survives the replacement,
         * but not its old meaning: it was an authoritative stored level and is
         * now a projection, nullable, rewritten from the proof on every store,
         * and forbidden from deciding anything in either direction. That
         * contract is pinned by TokenAssuranceSchemaTest and TokenEvidenceTest;
         * banning the column here would contradict them, which is exactly what
         * an earlier draft of this list did.
         */
        foreach (['token_id', 'amr', 'credential_ids', 'issuing_session_id'] as $column) {
            self::assertFalse(
                Schema::hasColumn('auth_token_assurances', $column),
                "Legacy column {$column} survived the replacement.",
            );
        }
    }

    /*
     * Reversibility is NOT asserted here, deliberately. An explicit test would
     * be weaker than what already runs: this class uses DatabaseMigrations,
     * which migrates and rolls back around EVERY test in it, so a down() that
     * left either table half-dropped would fail the whole file rather than one
     * assertion. Adding a hasTable() check on top would read as coverage while
     * proving less than the harness already does.
     */
}
