<?php

declare(strict_types=1);

use Fissible\Vouch\Delivery\SmsIdentifierAudit;
use Fissible\Vouch\Models\AuthIdentifier;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('classifies stored phone rows without rewriting or exposing values', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'phone', 'value' => '+14155552671']);
    AuthIdentifier::create(['user_id' => 2, 'type' => 'phone', 'value' => '+1 416 555 2671']);
    AuthIdentifier::create(['user_id' => 3, 'type' => 'phone', 'value' => '+1415']);
    AuthIdentifier::create(['user_id' => 4, 'type' => 'email', 'value' => 'ada@example.com']);

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
