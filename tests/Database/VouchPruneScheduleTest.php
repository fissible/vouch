<?php

declare(strict_types=1);

use Fissible\Vouch\Console\CommandExit;
use Fissible\Vouch\Console\VouchPruneSchedule;

it('pins the three-way command exit protocol', function (): void {
    expect(array_map(
        static fn (CommandExit $exit): array => [$exit->name, $exit->value],
        CommandExit::cases(),
    ))->toBe([
        ['Success', 0],
        ['Failure', 1],
        ['DeliveryHealth', 2],
    ]);
});

it('completes normally for a clean prune without sending a worker alert', function (): void {
    $alerts = [];

    VouchPruneSchedule::after(
        CommandExit::Success->value,
        'clean aggregate',
        function (string $output) use (&$alerts): void {
            $alerts[] = $output;
        },
    );

    expect($alerts)->toBe([]);
});

it('routes status two to delivery health and still completes normally', function (): void {
    $alerts = [];

    VouchPruneSchedule::after(
        CommandExit::DeliveryHealth->value,
        "  two expired-undelivered rows\n",
        function (string $output) use (&$alerts): void {
            $alerts[] = $output;
        },
    );

    expect($alerts)->toBe(['two expired-undelivered rows']);
});

it('throws for prune failure and unknown statuses instead of misrouting them', function (int $status): void {
    expect(fn () => VouchPruneSchedule::after(
        $status,
        'not delivery health',
        static function (): void {
            throw new RuntimeException('The worker-health callback must not run.');
        },
    ))->toThrow(RuntimeException::class, "status {$status}");
})->with([
    'prune failure' => [CommandExit::Failure->value],
    'unknown contract value' => [9],
]);
