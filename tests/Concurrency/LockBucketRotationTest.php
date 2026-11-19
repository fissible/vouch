<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Recovery\CredentialRecovery;
use Fissible\Vouch\Recovery\CredentialRecoveryRequest;
use Fissible\Vouch\Support\IssuanceLockBucket;
use Fissible\Vouch\Support\LockBucketSecret;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Fissible\Vouch\Verification\IdentifierVerificationRequest;
use Fissible\Vouch\Verification\IdentifierVerifier;
use Illuminate\Database\Connection;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

/*
 * #16. The rotation overlap's whole claim: while a previous secret is set, an
 * updated process takes the bucket a process still on the OLD configuration
 * takes, so the two serialize mid-rollout.
 *
 * A second connection plays the old-config process by holding the bucket the old
 * secret derives. An updated issuance must then block on it. The control is the
 * same issuance with the new secret alone, which must NOT block: that is the
 * uncoordinated rotation the overlap exists to prevent, and without the control a
 * test that blocked for any reason would pass.
 *
 * SQLite is skipped: lockForUpdate is a no-op there, and the database-wide write
 * lock is the mutex.
 */
uses(RefreshDatabase::class);

const ROTATION_OLD_SECRET = 'oooooooooooooooooooooooooooooooo-old-rotation-secret';
const ROTATION_NEW_SECRET = 'nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn-new-rotation-secret';

beforeEach(function (): void {
    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite') {
        $this->markTestSkipped('Row locks are a no-op on SQLite.');
    }

    $default = Config::string('database.default');
    config(['database.connections.rotation_holder' => Config::array('database.connections.' . $default)]);

    app()->instance(OtpDelivery::class, new ArrayOtpDelivery());
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());
});

afterEach(function (): void {
    // beforeEach skips SQLite before configuring the holder, so there is none.
    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite') {
        return;
    }

    $holder = DB::connection('rotation_holder');

    if ($holder->transactionLevel() > 0) {
        $holder->rollBack();
    }

    DB::purge('rotation_holder');
});

function rotationSecrets(string $current, ?string $previous = null): void
{
    config([
        LockBucketSecret::KEY => $current,
        LockBucketSecret::LEGACY_KEY => null,
        LockBucketSecret::PREVIOUS_KEY => $previous,
    ]);
}

/** An address whose bucket differs under the two secrets, so the cases are distinct. */
function rotationAddress(string $ceremony): string
{
    for ($i = 0; $i < 100; $i++) {
        $address = sprintf('rotation-%d@acme.example', $i);
        rotationSecrets(ROTATION_OLD_SECRET);
        $old = IssuanceLockBucket::for($ceremony, 'email', $address);
        rotationSecrets(ROTATION_NEW_SECRET);

        if (IssuanceLockBucket::for($ceremony, 'email', $address) !== $old) {
            return $address;
        }
    }

    throw new RuntimeException('Every probed address shared a bucket under both secrets.');
}

function rotationBucketUnder(string $secret, string $ceremony, string $address): int
{
    rotationSecrets($secret);

    return IssuanceLockBucket::for($ceremony, 'email', $address);
}

/** The old-config process: hold one issuance bucket on a separate connection. */
function holdRotationBucket(int $bucket): void
{
    $holder = DB::connection('rotation_holder');
    $holder->beginTransaction();

    $row = $holder->table(IssuanceLockBucket::TABLE)->where('bucket', $bucket)->lockForUpdate()->first();

    if ($row === null) {
        throw new RuntimeException("Bucket {$bucket} is not seeded.");
    }
}

function shortenRotationLockWait(Connection $connection): void
{
    match ($connection->getDriverName()) {
        'mysql' => $connection->statement('SET SESSION innodb_lock_wait_timeout = 1'),
        'pgsql' => $connection->statement("SELECT set_config('lock_timeout', '1s', false)"),
        default => throw new RuntimeException('Unsupported rotation driver.'),
    };
}

/** True when the issuance completed, false when it timed out waiting for a bucket. */
function rotationIssuanceCompletes(string $ceremony, string $address): bool
{
    $connection = DB::connection();
    shortenRotationLockWait($connection);

    try {
        $ceremony === 'recovery'
            ? app(CredentialRecovery::class)->request(new CredentialRecoveryRequest(
                type: 'email',
                submittedIdentifier: $address,
                tenantId: null,
                clientIp: '203.0.113.20',
            ))
            : app(IdentifierVerifier::class)->request(new IdentifierVerificationRequest(
                type: 'email',
                submittedIdentifier: $address,
                tenantId: null,
                clientIp: '203.0.113.20',
            ));

        return true;
    } catch (QueryException|DeadlockException $exception) {
        // Only a lock-wait timeout counts as "blocked". Anything else is a
        // broken premise and must fail the test with its own message. Inside a
        // nested transaction Laravel rethrows MySQL's 1205 as DeadlockException.
        $code = (string) $exception->getCode();
        $message = $exception->getMessage();

        if ($code === '55P03' || str_contains($message, 'Lock wait timeout exceeded')) {
            return false;
        }

        throw $exception;
    }
}

function rotationLiveProofs(string $ceremony, string $address): int
{
    $table = $ceremony === 'recovery' ? 'auth_recovery_proofs' : 'auth_identifier_verifications';

    return DB::table($table)
        ->where('identifier_value', $address)
        ->whereNull('superseded_at')
        ->count();
}

it('blocks an updated issuance on the bucket an old-config process holds', function (string $ceremony): void {
    $address = rotationAddress($ceremony);
    $old = rotationBucketUnder(ROTATION_OLD_SECRET, $ceremony, $address);

    holdRotationBucket($old);
    rotationSecrets(ROTATION_NEW_SECRET, ROTATION_OLD_SECRET);

    expect(rotationIssuanceCompletes($ceremony, $address))->toBeFalse()
        ->and(rotationLiveProofs($ceremony, $address))->toBe(0);
})->with(['recovery', 'verification']);

it('blocks an updated issuance on its own new bucket too', function (string $ceremony): void {
    $address = rotationAddress($ceremony);
    $new = rotationBucketUnder(ROTATION_NEW_SECRET, $ceremony, $address);

    holdRotationBucket($new);
    rotationSecrets(ROTATION_NEW_SECRET, ROTATION_OLD_SECRET);

    expect(rotationIssuanceCompletes($ceremony, $address))->toBeFalse();
})->with(['recovery', 'verification']);

it('does not serialize with the old bucket once the overlap is removed', function (string $ceremony): void {
    /*
     * The control, and the failure the overlap prevents: the new secret alone
     * takes a different bucket, so it proceeds past a held old one.
     */
    $address = rotationAddress($ceremony);
    $old = rotationBucketUnder(ROTATION_OLD_SECRET, $ceremony, $address);

    holdRotationBucket($old);
    rotationSecrets(ROTATION_NEW_SECRET);

    expect(rotationIssuanceCompletes($ceremony, $address))->toBeTrue()
        ->and(rotationLiveProofs($ceremony, $address))->toBe(1);
})->with(['recovery', 'verification']);
