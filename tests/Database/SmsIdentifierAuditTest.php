<?php

declare(strict_types=1);

use Fissible\Vouch\Delivery\SmsIdentifierAudit;
use Fissible\Vouch\Models\AuthIdentifier;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Artisan;
use Symfony\Component\Console\Exception\InvalidOptionException;

uses(RefreshDatabase::class);

function seedSmsAuditRows(): void
{
    AuthIdentifier::create(['user_id' => 1, 'type' => 'phone', 'value' => '+14155552671']);
    AuthIdentifier::create(['user_id' => 2, 'type' => 'phone', 'value' => '+1 416 555 2671']);
    AuthIdentifier::create(['user_id' => 3, 'type' => 'phone', 'value' => '+1415']);
    AuthIdentifier::create(['user_id' => 4, 'type' => 'email', 'value' => 'ada@example.com']);
}

it('classifies stored phone rows without rewriting them', function (): void {
    seedSmsAuditRows();

    $report = app(SmsIdentifierAudit::class)->report();

    expect($report)->toBe([
        'total' => 3,
        'canonical' => 1,
        'needs_normalization' => 1,
        'invalid' => 1,
        'countries' => ['CA' => 1, 'US' => 1],
    ])
        ->and(AuthIdentifier::query()->where('type', 'phone')->pluck('value')->sort()->values()->all())
        ->toBe(['+1 416 555 2671', '+1415', '+14155552671']);
});

it('renders aggregate SMS audit output without exposing identifier values', function (array $arguments): void {
    seedSmsAuditRows();

    expect(Artisan::call('vouch:sms-identifiers:audit', $arguments))->toBe(0);

    $output = Artisan::output();

    expect($output)->toContain('3')
        ->and($output)->not->toContain('4155552671')
        ->and($output)->not->toContain('+1415');
})->with([
    [['--json' => true]],
    [[]],
]);

it('renders JSON audit output without table formatting', function (): void {
    seedSmsAuditRows();

    expect(Artisan::call('vouch:sms-identifiers:audit', ['--json' => true]))->toBe(0);

    $output = Artisan::output();
    $report = json_decode($output, true, flags: JSON_THROW_ON_ERROR);

    expect($report)->toBe([
        'total' => 3,
        'canonical' => 1,
        'needs_normalization' => 1,
        'invalid' => 1,
        'countries' => ['CA' => 1, 'US' => 1],
    ])
        ->and($output)->not->toContain('Total')
        ->and($output)->not->toContain('Country counts:');
});

it('renders the complete table and labeled country counts without JSON mode', function (): void {
    seedSmsAuditRows();

    expect(Artisan::call('vouch:sms-identifiers:audit'))->toBe(0);

    $output = Artisan::output();

    expect($output)
        ->toContain('Total')
        ->toContain('Canonical')
        ->toContain('Needs normalization')
        ->toContain('Invalid')
        ->toContain('Country counts:')
        ->toContain('"CA":1')
        ->toContain('"US":1')
        ->not()->toContain('{"total"');
});

it('discriminates canonicalization, duplicate countries, and country ordering', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'phone', 'value' => '+14155552671']);
    AuthIdentifier::create(['user_id' => 2, 'type' => 'phone', 'value' => '+1 415 555 2671']);
    AuthIdentifier::create(['user_id' => 3, 'type' => 'phone', 'value' => '+44 20 7946 0958']);

    expect(app(SmsIdentifierAudit::class)->report())->toBe([
        'total' => 3,
        'canonical' => 1,
        'needs_normalization' => 2,
        'invalid' => 0,
        'countries' => ['GB' => 1, 'US' => 2],
    ]);
});

it('retains an empty country map when no identifier can be normalized', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'phone', 'value' => '+1415']);

    expect(app(SmsIdentifierAudit::class)->report()['countries'])->toBe([]);
});

it('does not accept subject lookup options and treats invalid rows as a survey result', function (): void {
    seedSmsAuditRows();

    $command = app(Kernel::class)->all()['vouch:sms-identifiers:audit'];
    $options = array_keys($command->getDefinition()->getOptions());

    expect($options)->toBe(['json'])
        ->and($command->getDefinition()->getArguments())->toBe([])
        ->and(Artisan::call('vouch:sms-identifiers:audit', ['--json' => true]))->toBe(0);

    expect(fn (): int => Artisan::call('vouch:sms-identifiers:audit', ['--value' => '+1415']))
        ->toThrow(InvalidOptionException::class, 'option does not exist');
});
