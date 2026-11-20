<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use Fissible\Vouch\Console\RetentionManifest;
use Fissible\Vouch\Support\LockBucket;
use Fissible\Vouch\Support\LockBucketSecret;
use Fissible\Vouch\Support\SubjectLockBucket;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\CredentialLockManager;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Test;

/**
 * #17. The subject mutex as a fixed set of keyed buckets.
 *
 * 2.4 Task 5a gave each subject a permanent anchor row so a subject with no
 * session still serializes. That kept one row per subject ever issued a token,
 * naming the subject, surviving the host deleting the user. A bucket keeps the
 * serialization and discards the identity, as #46 did for identifiers.
 *
 * These assert observable properties. Whether two transactions exclude each
 * other is proven against real engines in SubjectLockContentionTest.
 */
final class SubjectLockTest extends TestCase
{
    use DatabaseMigrations;

    /** @return array<int, class-string> */
    protected function getPackageProviders($app): array
    {
        return [VouchServiceProvider::class];
    }

    private function locks(): CredentialLockManager
    {
        return app(CredentialLockManager::class);
    }

    /** @return list<int> */
    private function bucketRows(): array
    {
        return array_values(array_map(
            static fn (mixed $bucket): int => is_numeric($bucket) ? (int) $bucket : -1,
            DB::table(SubjectLockBucket::TABLE)->orderBy('bucket')->pluck('bucket')->all(),
        ));
    }

    #[Test]
    public function the_table_is_a_seeded_bucket_space(): void
    {
        self::assertSame(['bucket'], DB::connection()->getSchemaBuilder()->getColumnListing(SubjectLockBucket::TABLE));
        self::assertSame(range(0, LockBucket::COUNT - 1), $this->bucketRows());
    }

    #[Test]
    public function locking_a_subject_writes_no_row_and_retains_no_identity(): void
    {
        /*
         * The point of #17: the old anchor inserted "provider:id" on first use
         * and kept it forever. A subject with no session must still serialize,
         * and now does so on a row that existed before it asked.
         */
        self::assertSame(0, DB::table('auth_sessions')->count());

        DB::transaction(function (): void {
            $this->locks()->acquire(DB::connection(), SubjectKey::of('App\\Models\\User', '7'), []);
        });

        self::assertSame(range(0, LockBucket::COUNT - 1), $this->bucketRows());
    }

    #[Test]
    public function it_keys_the_bucket_by_provider_and_id_together(): void
    {
        /*
         * Same id under two providers, and ids that differ only as strings. A
         * bucket keyed on half the identity would merge these every time, not
         * one time in 4096.
         */
        $keys = [
            SubjectKey::of('App\\Models\\User', '7'),
            SubjectKey::of('App\\Models\\Admin', '7'),
            SubjectKey::of('App\\Models\\User', '07'),
        ];

        foreach ($keys as $key) {
            self::assertSame(
                [LockBucket::under(LockBucketSecret::current(), SubjectLockBucket::DOMAIN, $key->provider, $key->id)],
                SubjectLockBucket::buckets($key),
            );
        }

        // Positive control: across many ids, the mapping really depends on both halves.
        $differsByProvider = false;
        $differsAsString = false;

        for ($i = 1; $i <= 20; $i++) {
            $user = SubjectLockBucket::buckets(SubjectKey::of('App\\Models\\User', (string) $i));
            $differsByProvider = $differsByProvider
                || $user !== SubjectLockBucket::buckets(SubjectKey::of('App\\Models\\Admin', (string) $i));
            $differsAsString = $differsAsString
                || $user !== SubjectLockBucket::buckets(SubjectKey::of('App\\Models\\User', '0' . $i));
        }

        self::assertTrue($differsByProvider);
        self::assertTrue($differsAsString);
    }

    #[Test]
    public function it_takes_both_buckets_during_a_rotation_overlap(): void
    {
        $subject = SubjectKey::of('App\\Models\\User', '7');
        config([LockBucketSecret::KEY => str_repeat('n', 40), LockBucketSecret::LEGACY_KEY => null]);
        $new = SubjectLockBucket::buckets($subject);
        config([LockBucketSecret::KEY => str_repeat('o', 40)]);
        $old = SubjectLockBucket::buckets($subject);

        config([LockBucketSecret::KEY => str_repeat('n', 40), LockBucketSecret::PREVIOUS_KEY => str_repeat('o', 40)]);
        $both = array_values(array_unique([...$new, ...$old]));
        sort($both);

        self::assertSame($both, SubjectLockBucket::buckets($subject));
    }

    #[Test]
    public function it_locks_the_subject_before_any_credential(): void
    {
        /*
         * Lock ORDER is the deadlock protocol: subject first, then credentials
         * in canonical string order. Ids chosen so string and numeric order
         * disagree.
         */
        /** @var list<string> $order */
        $order = [];
        $manager = new class($order) extends CredentialLockManager {
            /** @param list<string> $order */
            public function __construct(public array &$order) {}

            protected function lockSubject(SubjectKey $subject): void
            {
                $this->order[] = 'subject:' . $subject->toString();
            }

            protected function lockCredential(string $credentialId): void
            {
                $this->order[] = 'credential:' . $credentialId;
            }
        };

        $manager->acquire(
            DB::connection(),
            SubjectKey::of('App\\Models\\User', '7'),
            ['9', '100', '10'],
        );

        self::assertSame(
            ['subject:App\\Models\\User:7', 'credential:10', 'credential:100', 'credential:9'],
            $order,
        );
    }

    #[Test]
    public function it_refuses_when_the_bucket_space_is_not_seeded(): void
    {
        /*
         * A missing bucket must fail loudly. Silently locking nothing is the
         * defect 5a existed to remove.
         */
        DB::table(SubjectLockBucket::TABLE)->delete();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not seeded');

        DB::transaction(function (): void {
            $this->locks()->acquire(DB::connection(), SubjectKey::of('App\\Models\\User', '7'), []);
        });
    }

    #[Test]
    public function maintenance_leaves_the_bucket_space_intact(): void
    {
        DB::transaction(fn () => $this->locks()->acquire(DB::connection(), SubjectKey::of('App\\Models\\User', '7'), []));

        Artisan::call('vouch:prune');

        self::assertSame(range(0, LockBucket::COUNT - 1), $this->bucketRows());
    }

    #[Test]
    public function the_manifest_says_no_subject_is_retained(): void
    {
        $reason = RetentionManifest::retained()[SubjectLockBucket::TABLE] ?? '';

        self::assertStringContainsString('#17', $reason);
        self::assertStringContainsString('no subject is retained', $reason);
        self::assertStringNotContainsString('grows', $reason);
    }

    #[Test]
    public function the_table_has_no_foreign_key(): void
    {
        /*
         * A mutex must not cascade-delete with the user, nor couple the most
         * contended statement in the protocol to a lookup on the host's users.
         */
        self::assertSame([], DB::connection()->getSchemaBuilder()->getForeignKeys(SubjectLockBucket::TABLE));
    }
}
