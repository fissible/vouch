<?php

declare(strict_types=1);

use Fissible\Vouch\Delivery\DatabaseDeliveryEconomics;
use Fissible\Vouch\Delivery\DeliveryEconomicsConfiguration;
use Fissible\Vouch\Delivery\DeliveryEconomicsDecision;
use Fissible\Vouch\Delivery\DeliveryEconomicsRequest;
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
            ->and(array_count_values($results)[DeliveryEconomicsDecision::Permitted->name] ?? 0)->toBe(1)
            ->and(array_count_values($results)[DeliveryEconomicsDecision::Refused->name] ?? 0)->toBe(1);
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
