<?php

declare(strict_types=1);

use Fissible\Vouch\Delivery\DatabaseDeliveryEconomics;
use Fissible\Vouch\Delivery\DeliveryEconomicsConfiguration;
use Fissible\Vouch\Delivery\DeliveryEconomicsRequest;
use Fissible\Vouch\Delivery\DeliveryReservationDecision;
use Fissible\Vouch\Support\BoundedLockWait;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Support\LockContention;
use Fissible\Vouch\Throttle\ThrottleKey;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;

uses(DatabaseMigrations::class);

beforeEach(function (): void {
    if (! function_exists('pcntl_fork')) {
        $this->markTestSkipped('The delivery economics race requires pcntl_fork.');
    }

    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'The delivery economics race needs two processes connected to one file-backed database.',
        );
    }
});

it('admits only one concurrent reservation at the daily ceiling', function (): void {
    $directory = sys_get_temp_dir() . '/vouch-delivery-economics-' . bin2hex(random_bytes(8));

    if (! mkdir($directory, 0700) && ! is_dir($directory)) {
        throw new RuntimeException('Could not create delivery economics race directory.');
    }

    $release = $directory . '/release';
    $children = [];
    DB::purge();

    try {
        foreach ([0, 1] as $index) {
            $pid = pcntl_fork();

            if ($pid === -1) {
                throw new RuntimeException('Could not fork delivery economics race child.');
            }

            if ($pid === 0) {
                $ready = $directory . "/ready-{$index}";
                $output = $directory . "/output-{$index}";

                try {
                    $connection = DB::connection();
                    $connection->getPdo();

                    if ($connection->getDriverName() === 'sqlite') {
                        $connection->statement('PRAGMA busy_timeout = 5000');
                    }

                    touch($ready);
                    $deadline = microtime(true) + 10.0;

                    while (! is_file($release)) {
                        if (microtime(true) >= $deadline) {
                            throw new RuntimeException('Timed out waiting for delivery economics release.');
                        }

                        usleep(1_000);
                    }

                    $economics = new DatabaseDeliveryEconomics(
                        $connection,
                        new DatabaseTime($connection),
                        app(ThrottleKey::class),
                        new DeliveryEconomicsConfiguration(10, null, ['US']),
                        new BoundedLockWait($connection),
                        new LockContention(),
                    );

                    $result = $economics->reserve(new DeliveryEconomicsRequest(
                        'email_otp',
                        'email',
                        null,
                        null,
                        10,
                        false,
                        str_repeat((string) ($index + 1), 64),
                    ));

                    file_put_contents($output, $result->name);
                    exit(0);
                } catch (Throwable $exception) {
                    file_put_contents($output, $exception::class . ': ' . $exception->getMessage());
                    exit(1);
                }
            }

            $children[] = $pid;
        }

        foreach ([0, 1] as $index) {
            $deadline = microtime(true) + 10.0;

            while (! is_file($directory . "/ready-{$index}")) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('A delivery economics child did not reach the ready barrier.');
                }

                usleep(1_000);
            }
        }

        touch($release);

        foreach ($children as $pid) {
            pcntl_waitpid($pid, $status);

            if (pcntl_wexitstatus($status) !== 0) {
                throw new RuntimeException('A delivery economics child failed.');
            }
        }

        $results = array_map(
            static fn (int $index): string => trim((string) file_get_contents($directory . "/output-{$index}")),
            [0, 1],
        );

        expect($results)->toHaveCount(2)
            ->and(array_count_values($results)[DeliveryReservationDecision::Permitted->name] ?? 0)->toBe(1)
            ->and(array_count_values($results)[DeliveryReservationDecision::SpendCeiling->name] ?? 0)->toBe(1);
    } finally {
        foreach ($children as $pid) {
            pcntl_waitpid($pid, $status, WNOHANG);
        }

        foreach (glob($directory . '/*') ?: [] as $file) {
            unlink($file);
        }

        rmdir($directory);
    }
});

it('charges one reservation once when two workers race on one key', function (): void {
    $directory = sys_get_temp_dir() . '/vouch-delivery-economics-' . bin2hex(random_bytes(8));

    if (! mkdir($directory, 0700) && ! is_dir($directory)) {
        throw new RuntimeException('Could not create delivery economics race directory.');
    }

    $release = $directory . '/release';
    $children = [];
    DB::purge();

    try {
        foreach ([0, 1] as $index) {
            $pid = pcntl_fork();

            if ($pid === -1) {
                throw new RuntimeException('Could not fork delivery economics race child.');
            }

            if ($pid === 0) {
                $ready = $directory . "/ready-{$index}";
                $output = $directory . "/output-{$index}";

                try {
                    $connection = DB::connection();
                    $connection->getPdo();

                    if ($connection->getDriverName() === 'sqlite') {
                        $connection->statement('PRAGMA busy_timeout = 5000');
                    }

                    touch($ready);
                    $deadline = microtime(true) + 10.0;

                    while (! is_file($release)) {
                        if (microtime(true) >= $deadline) {
                            throw new RuntimeException('Timed out waiting for delivery economics release.');
                        }

                        usleep(1_000);
                    }

                    $economics = new DatabaseDeliveryEconomics(
                        $connection,
                        new DatabaseTime($connection),
                        app(ThrottleKey::class),
                        new DeliveryEconomicsConfiguration(null, null, ['US']),
                        new BoundedLockWait($connection),
                        new LockContention(),
                    );

                    $result = $economics->reserve(new DeliveryEconomicsRequest(
                        'email_otp',
                        'email',
                        null,
                        null,
                        10,
                        false,
                        str_repeat('s', 64),
                    ));

                    file_put_contents($output, $result->name);
                    exit(0);
                } catch (Throwable $exception) {
                    file_put_contents($output, $exception::class . ': ' . $exception->getMessage());
                    exit(1);
                }
            }

            $children[] = $pid;
        }

        foreach ([0, 1] as $index) {
            $deadline = microtime(true) + 10.0;

            while (! is_file($directory . "/ready-{$index}")) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('A delivery economics child did not reach the ready barrier.');
                }

                usleep(1_000);
            }
        }

        touch($release);

        foreach ($children as $pid) {
            pcntl_waitpid($pid, $status);

            if (pcntl_wexitstatus($status) !== 0) {
                throw new RuntimeException('A delivery economics child failed.');
            }
        }

        $results = array_map(
            static fn (int $index): string => trim((string) file_get_contents($directory . "/output-{$index}")),
            [0, 1],
        );

        $globalSpent = DB::table('auth_delivery_spend')->where('scope', 'global')->value('spent_minor');
        $tenantSpent = DB::table('auth_delivery_spend')->where('scope', 'tenant')->value('spent_minor');

        expect($results)->toHaveCount(2)
            ->and(array_count_values($results)[DeliveryReservationDecision::Permitted->name] ?? 0)->toBe(2)
            ->and($globalSpent)->toBeInt()->toBe(10)
            ->and($tenantSpent)->toBeInt()->toBe(10)
            ->and(DB::table('auth_delivery_spend_reservations')->count())->toBe(2);
    } finally {
        foreach ($children as $pid) {
            pcntl_waitpid($pid, $status, WNOHANG);
        }

        foreach (glob($directory . '/*') ?: [] as $file) {
            unlink($file);
        }

        rmdir($directory);
    }
});

it('preserves a concurrent spend while a stale window rolls over', function (): void {
    $directory = sys_get_temp_dir() . '/vouch-delivery-rollover-' . bin2hex(random_bytes(8));

    if (! mkdir($directory, 0700) && ! is_dir($directory)) {
        throw new RuntimeException('Could not create delivery rollover probe directory.');
    }

    $release = $directory . '/release';
    $started = $directory . '/started';
    $output = $directory . '/output';
    $children = [];
    $tenantId = 'tenant-a';
    $keys = app(ThrottleKey::class);
    $global = $keys->global();
    $tenant = $keys->tenant($tenantId);
    $oldWindow = now()->subDay()->startOfDay()->format('Y-m-d H:i:s');
    $today = now()->startOfDay()->format('Y-m-d H:i:s');

    DB::table('auth_delivery_spend')->insert([
        [
            'scope' => 'global',
            'subject_digest' => $global->digest,
            'window_started_at' => $oldWindow,
            'spent_minor' => 10,
            'created_at' => now(),
            'updated_at' => now(),
        ],
        [
            'scope' => 'tenant',
            'subject_digest' => $tenant->digest,
            'window_started_at' => $oldWindow,
            'spent_minor' => 10,
            'created_at' => now(),
            'updated_at' => now(),
        ],
    ]);

    DB::purge();

    try {
        $pid = pcntl_fork();

        if ($pid === -1) {
            throw new RuntimeException('Could not fork delivery rollover child.');
        }

        if ($pid === 0) {
            try {
                $connection = DB::connection();
                $connection->getPdo();

                if ($connection->getDriverName() === 'sqlite') {
                    $connection->statement('PRAGMA busy_timeout = 5000');
                }

                touch($started);
                $deadline = microtime(true) + 10.0;

                while (! is_file($release)) {
                    if (microtime(true) >= $deadline) {
                        throw new RuntimeException('Timed out waiting for delivery rollover release.');
                    }

                    usleep(1_000);
                }

                $economics = new DatabaseDeliveryEconomics(
                    $connection,
                    new DatabaseTime($connection),
                    app(ThrottleKey::class),
                    new DeliveryEconomicsConfiguration(100, null, ['US']),
                    new BoundedLockWait($connection),
                    new LockContention(),
                );

                $result = $economics->reserve(new DeliveryEconomicsRequest(
                    'email_otp',
                    'email',
                    $tenantId,
                    null,
                    10,
                    false,
                    str_repeat('r', 64),
                ));

                file_put_contents($output, $result->name);
                exit(0);
            } catch (Throwable $exception) {
                file_put_contents($output, $exception::class . ': ' . $exception->getMessage());
                exit(1);
            }
        }

        $children[] = $pid;
        $deadline = microtime(true) + 10.0;

        while (! is_file($started)) {
            if (microtime(true) >= $deadline) {
                throw new RuntimeException('The delivery rollover child did not reach the barrier.');
            }

            usleep(1_000);
        }

        $parent = DB::connection();
        $sqliteImmediate = $parent->getDriverName() === 'sqlite';

        if ($sqliteImmediate) {
            $parent->statement('BEGIN IMMEDIATE');
        } else {
            $parent->beginTransaction();
        }

        $row = $parent->table('auth_delivery_spend')
            ->where('scope', 'global')
            ->where('subject_digest', $global->digest)
            ->lockForUpdate()
            ->first();

        if ($row === null) {
            throw new RuntimeException('The delivery rollover probe could not lock its seeded row.');
        }

        $parent->table('auth_delivery_spend')
            ->where('id', $row->id)
            ->update([
                'window_started_at' => $today,
                'spent_minor' => 20,
                'updated_at' => now(),
            ]);

        touch($release);
        usleep(200_000);

        expect(is_file($output))->toBeFalse('The child did not wait on the locked rollover row.');

        if ($sqliteImmediate) {
            $parent->statement('COMMIT');
        } else {
            $parent->commit();
        }

        $status = 0;
        pcntl_waitpid($pid, $status);

        expect(pcntl_wifexited($status) ? pcntl_wexitstatus($status) : 255)->toBe(0)
            ->and(trim((string) file_get_contents($output)))->toBe(DeliveryReservationDecision::Permitted->name)
            ->and(DB::table('auth_delivery_spend')
                ->where('scope', 'global')
                ->value('spent_minor'))->toBeInt()->toBe(30);
    } finally {
        foreach ($children as $child) {
            pcntl_waitpid($child, $status, WNOHANG);
        }

        foreach (glob($directory . '/*') ?: [] as $file) {
            unlink($file);
        }

        rmdir($directory);
    }
});
