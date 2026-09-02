<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use Fissible\Vouch\Assurance\AssuranceReason;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\ResolvedToken;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * Issue #7 — the morph-map warning, proven for TOKEN records.
 *
 * SessionEvidenceTest establishes this for sessions. Tokens need it stated
 * separately and not by analogy: they are a different table, a different
 * reader, and the only reason the two agree today is that both canonicalize
 * through `getMorphClass()`. If the token reader ever diverged, the README's
 * warning would remain true of sessions and quietly false of the tokens a host
 * has already issued.
 *
 * `morphMap()` rather than `enforceMorphMap()`, following the session test:
 * the latter also sets Laravel's global requireMorphMap flag, which resetting
 * the map does not clear, so every model in every later suite would throw.
 */
final class MorphMapTokenIdentityTest extends TestCase
{
    use DatabaseMigrations;
    use UsesSanctumSchema;

    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [SanctumServiceProvider::class, VouchServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('auth.providers.users.model', TokenUser::class);
    }

    /** @return list<SatisfiedFactor> */
    private function factors(): array
    {
        return [
            new SatisfiedFactor(
                factorId: 'password',
                credentialId: '1',
                kind: FactorKind::Knowledge,
                strength: FactorStrength::Knowledge,
                isMultiFactor: false,
                userVerified: false,
                phishingResistant: false,
                authenticatorId: null,
                satisfiedAt: new \DateTimeImmutable('2026-09-01T10:00:00+00:00'),
            ),
        ];
    }

    #[Test]
    public function a_record_written_before_the_map_stops_binding_and_is_not_migrated(): void
    {
        /*
         * The exact sequence the documentation warns about: issue a token, then
         * register a map. The provider half of the stored subject key was the
         * class name; under the map the canonical provider is the alias, so the
         * record was minted under a different identity scheme.
         */
        $model = TokenUser::class;
        $beforeTheMap = SubjectKey::of((new $model)->getMorphClass(), 7);

        app(TokenAssuranceRecord::class)->store(
            'sanctum',
            'token-1',
            $beforeTheMap,
            null,
            ActorKind::Human,
            $this->factors(),
        );

        self::assertSame($model, $beforeTheMap->provider);

        Relation::morphMap(['vouch_user' => $model], false);

        try {
            $underTheMap = SubjectKey::of((new $model)->getMorphClass(), 7);
            self::assertSame('vouch_user', $underTheMap->provider);

            $read = app(TokenAssuranceRecord::class)->read(
                new ResolvedToken('sanctum', 'token-1', $underTheMap, true),
            );

            // Fails closed. Adopting it would assert that a subject nobody can
            // now resolve is this user.
            self::assertNull($read->evidence);
            self::assertSame(AssuranceReason::SubjectMismatch, $read->reason);

            // And nothing was rewritten on the way past. The record is intact;
            // only its interpretation moved.
            self::assertSame(
                $model . ':7',
                stringValue(DB::table('auth_token_assurances')->where('token_key', 'token-1')->value('subject_key')),
            );
        } finally {
            Relation::morphMap([], false);
        }
    }

    #[Test]
    public function the_same_record_binds_again_once_the_map_is_removed(): void
    {
        /*
         * The other half of §3a, on ONE row and in sequence: store, observe the
         * mismatch under the map, remove the map, read again.
         *
         * A separately stored record that binds after a map is added and
         * removed proves less than it appears to -- it never demonstrates that
         * the row which FAILED is the row that recovers. Recoverability is the
         * claim that makes the refusal safe to ship, so it has to be measured
         * on the record that was actually refused.
         */
        $model = TokenUser::class;
        $subject = SubjectKey::of((new $model)->getMorphClass(), 7);

        app(TokenAssuranceRecord::class)->store(
            'sanctum',
            'token-1',
            $subject,
            null,
            ActorKind::Human,
            $this->factors(),
        );

        Relation::morphMap(['vouch_user' => $model], false);

        try {
            $whileMapped = app(TokenAssuranceRecord::class)->read(
                new ResolvedToken('sanctum', 'token-1', SubjectKey::of((new $model)->getMorphClass(), 7), true),
            );

            self::assertSame(AssuranceReason::SubjectMismatch, $whileMapped->reason);
        } finally {
            Relation::morphMap([], false);
        }

        $afterRemoval = app(TokenAssuranceRecord::class)->read(
            new ResolvedToken('sanctum', 'token-1', SubjectKey::of((new $model)->getMorphClass(), 7), true),
        );

        self::assertSame(AssuranceReason::Sufficient, $afterRemoval->reason);
        self::assertNotNull($afterRemoval->evidence);

        // Nothing was rewritten at any point. The record is intact; only its
        // interpretation moved, which is the whole reason removal restores it.
        self::assertSame(
            $model . ':7',
            stringValue(DB::table('auth_token_assurances')->where('token_key', 'token-1')->value('subject_key')),
        );
    }
}
