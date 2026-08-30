<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
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
    public function the_dropped_table_still_has_no_runtime_authorization_consumer(): void
    {
        /*
         * The safety claim behind drop-and-recreate, asserted against src/.
         * AuthTokenAssurance may be referenced by the model and by fixtures; it
         * must not be READ on an authorization path, because then discarding
         * rows would be discarding live authority rather than dead fixture data.
         *
         * Scoped to Vouch-owned consumers, deliberately and no wider: a host's
         * raw SQL or reporting job is invisible here, which is exactly why the
         * upgrade note tells hosts about the drop instead of relying on this.
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

            // The model itself is the surface being described, and the new
            // record adapter legitimately owns the replacement table.
            if ($relative === 'Models/AuthTokenAssurance.php' || str_starts_with($relative, 'Tokens/')) {
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

        self::assertSame([], $offenders, 'A runtime consumer appeared; drop-and-recreate is no longer safe.');
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
         * A leftover acr/amr/credential_ids column is not inert: it is a cached
         * assurance level sitting beside the proof that replaced it, which is
         * precisely the shape Task 2a spent its existence removing from
         * auth_sessions. Nothing should be able to authorize from it again.
         */
        foreach (['token_id', 'acr', 'amr', 'credential_ids', 'issuing_session_id'] as $column) {
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
