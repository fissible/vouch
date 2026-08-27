<?php

declare(strict_types=1);

use Fissible\Vouch\Console\CommandExit;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Gate;

/*
 * `vouch:assurance-map` (2.3d Task 5b).
 *
 * Task 5a established the bound on typo detection: Gate::abilities() lists
 * only explicitly define()d abilities, and spatie's and Bouncer's live in the
 * database, so complete "unknown ability" detection needs a HOST-DECLARED
 * list. The command reports against both and says which source matched, so an
 * UNKNOWN row means "matched neither", not "does not exist".
 */

/**
 * @param  array<string, mixed>  $options
 * @return array<string, mixed>
 */
function assuranceMapJson(array $options = [], int $expectedExit = 0): array
{
    // The exit status is asserted here rather than left to individual tests:
    // a command that emits the right JSON and returns failure would otherwise
    // satisfy every report assertion in this file.
    $exit = Artisan::call('vouch:assurance-map', $options + ['--json' => true]);

    expect($exit)->toBe($expectedExit);

    $decoded = json_decode(Artisan::output(), true, 512, JSON_THROW_ON_ERROR);

    if (! is_array($decoded)) {
        throw new RuntimeException('Expected an assurance map report object.');
    }

    /** @var array<string, mixed> $decoded */
    return $decoded;
}

/**
 * The requirement rows, narrowed. json_decode hands back mixed, and every
 * assertion below reads columns off these rows.
 *
 * @param  array<string, mixed>  $options
 * @return list<array<string, mixed>>
 */
function assuranceMapRows(array $options = []): array
{
    $rows = assuranceMapJson($options)['requirements'] ?? null;

    if (! is_array($rows)) {
        throw new RuntimeException('Expected assurance map requirement rows.');
    }

    /** @var list<array<string, mixed>> $rows */
    return $rows;
}

it('reports an empty map without complaining', function (): void {
    config(['vouch.assurance_requirements' => []]);

    expect(Artisan::call('vouch:assurance-map'))->toBe(CommandExit::Success->value);
});

it('lists every configured requirement', function (): void {
    config(['vouch.assurance_requirements' => [
        'invoices.approve' => 'aal2',
        'users.impersonate' => 'aal3',
    ]]);

    $report = assuranceMapRows();

    expect(array_column($report, 'level', 'ability'))
        ->toBe(['invoices.approve' => 'aal2', 'users.impersonate' => 'aal3']);
});

it('attributes an ability defined on the Gate to the gate', function (): void {
    Gate::define('invoices.approve', fn (): bool => true);
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal2']]);

    expect(array_column(assuranceMapRows(), 'source', 'ability'))
        ->toBe(['invoices.approve' => 'gate']);
});

it('attributes an ability the host declared to the declaration', function (): void {
    config([
        'vouch.declared_abilities' => ['invoices.approve'],
        'vouch.assurance_requirements' => ['invoices.approve' => 'aal2'],
    ]);

    expect(array_column(assuranceMapRows(), 'source', 'ability'))
        ->toBe(['invoices.approve' => 'declared']);
});

it('marks an ability that matches neither source as unknown', function (): void {
    config([
        'vouch.declared_abilities' => ['invoices.approve'],
        'vouch.assurance_requirements' => ['invoices.aprove' => 'aal2'],
    ]);

    expect(array_column(assuranceMapRows(), 'source', 'ability'))
        ->toBe(['invoices.aprove' => 'unknown']);
});

it('counts the unknown requirements so a typo is visible without reading rows', function (): void {
    config([
        'vouch.declared_abilities' => ['invoices.approve'],
        'vouch.assurance_requirements' => [
            'invoices.approve' => 'aal2',
            'invoices.aprove' => 'aal2',
        ],
    ]);

    expect(assuranceMapJson()['unknown'])->toBe(1);
});

it('still succeeds on an unknown ability by default', function (): void {
    // Installing the package must never break a working app. A typo is
    // reported; making it fatal is the host's choice.
    config(['vouch.assurance_requirements' => ['invoices.aprove' => 'aal2']]);

    expect(Artisan::call('vouch:assurance-map'))->toBe(CommandExit::Success->value);
});

it('fails on an unknown ability when asked to be strict', function (): void {
    config([
        'vouch.declared_abilities' => ['invoices.approve'],
        'vouch.assurance_requirements' => ['invoices.aprove' => 'aal2'],
    ]);

    expect(Artisan::call('vouch:assurance-map', ['--strict' => true]))->toBe(CommandExit::Failure->value);
});

it('succeeds under strict when every ability is accounted for', function (): void {
    config([
        'vouch.declared_abilities' => ['invoices.approve'],
        'vouch.assurance_requirements' => ['invoices.approve' => 'aal2'],
    ]);

    expect(Artisan::call('vouch:assurance-map', ['--strict' => true]))->toBe(CommandExit::Success->value);
});

/*
 * `vouch.assurance_strict` refuses the BOOT, and this command is exempted from
 * that refusal so a locked-out host can still find the offending key. That
 * cannot be asserted from here: this file's application has already booted, so
 * setting the flag now would exercise nothing. The proof lives in
 * AssuranceStrictBootDiagnosticTest, which boots with the flag set and the
 * argv of a real `php artisan vouch:assurance-map` invocation.
 */

it('names the unknown abilities in its human output, not just a count', function (): void {
    config(['vouch.assurance_requirements' => ['invoices.aprove' => 'aal2']]);

    Artisan::call('vouch:assurance-map');

    expect(Artisan::output())->toContain('invoices.aprove');
});

/*
 * Survey item 5: two host configurations silently disable Gate enforcement and
 * neither is detectable from inside Vouch at runtime. The command is where a
 * host finds out.
 */

it('warns when the configured user model does not route can() to the Gate', function (): void {
    // Bouncer's trait overrides can() on a model extending
    // Illuminate\Foundation\Auth\User with no collision and no warning from
    // PHP. Every Gate-routed check on that model is then unenforceable.
    config([
        'auth.providers.users.model' => Fissible\Vouch\Tests\Support\Authorization\Models\BouncerProbeUser::class,
        'vouch.assurance_requirements' => ['invoices.approve' => 'aal2'],
    ]);

    expect(assuranceMapJson()['user_model_routes_to_gate'])->toBeFalse();
});

it('reports a stock user model as routing can() to the Gate', function (): void {
    config([
        'auth.providers.users.model' => Fissible\Vouch\Tests\Support\Authorization\Models\PlainProbeUser::class,
        'vouch.assurance_requirements' => ['invoices.approve' => 'aal2'],
    ]);

    expect(assuranceMapJson()['user_model_routes_to_gate'])->toBeTrue();
});

it('reports a spatie user model as routing can() to the Gate', function (): void {
    // spatie never declares can(), so HasRoles leaves enforcement intact.
    config([
        'auth.providers.users.model' => Fissible\Vouch\Tests\Support\Authorization\Models\SpatieProbeUser::class,
        'vouch.assurance_requirements' => ['invoices.approve' => 'aal2'],
    ]);

    expect(assuranceMapJson()['user_model_routes_to_gate'])->toBeTrue();
});

it('does not fail merely because the user model bypasses the Gate', function (): void {
    // It is a warning, not a verdict: a host may deliberately use Bouncer's
    // trait and rely on the middleware, which does not go through the Gate.
    config([
        'auth.providers.users.model' => Fissible\Vouch\Tests\Support\Authorization\Models\BouncerProbeUser::class,
        'vouch.assurance_requirements' => ['invoices.approve' => 'aal2'],
    ]);

    expect(Artisan::call('vouch:assurance-map'))->toBe(CommandExit::Success->value);
});

it('survives a user model class that is not installed', function (): void {
    config([
        'auth.providers.users.model' => 'App\\Models\\ThatWasNeverPublished',
        'vouch.assurance_requirements' => ['invoices.approve' => 'aal2'],
    ]);

    expect(Artisan::call('vouch:assurance-map'))->toBe(CommandExit::Success->value)
        ->and(assuranceMapJson()['user_model_routes_to_gate'])->toBeNull();
});

it('does not let a Gate definition satisfy strict mode', function (): void {
    /*
     * Strict mode answers only to `vouch.declared_abilities`. Gate::abilities()
     * is not usable as the strict source for two reasons: it is empty at boot,
     * where the strict refusal has to happen, and a stale or unrelated
     * `Gate::define()` left over from another feature would silently vouch for
     * a typo. The report below still ATTRIBUTES an ability to the Gate — that
     * is a diagnostic, not a licence.
     */
    Gate::define('invoices.aprove', fn (): bool => true);
    config([
        'vouch.declared_abilities' => ['invoices.approve'],
        'vouch.assurance_requirements' => ['invoices.aprove' => 'aal2'],
    ]);

    expect(Artisan::call('vouch:assurance-map', ['--strict' => true]))->toBe(CommandExit::Failure->value);
});

/*
 * Which middleware groups actually carry the enforcement. A host whose
 * protected routes live in a custom group is otherwise relying on the Gate
 * hook alone, which Task 5a measured as bypassable — and nothing else in the
 * system would tell them.
 */

it('reports the middleware groups the enforcement is installed in', function (): void {
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal2']]);

    expect(assuranceMapJson()['enforced_groups'])->toContain('web')->toContain('api');
});

it('does not claim a group it was never pushed into', function (): void {
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal2']]);

    expect(assuranceMapJson()['enforced_groups'])->not->toContain('admin');
});
