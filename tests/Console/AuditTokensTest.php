<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Route;

/*
 * 2.4 Task 6 -- vouch:audit-tokens.
 *
 * §6.2 named a live MFA bypass: an endpoint minting a token on a password
 * alone is worth as much as the panel it unlocks. Task 4 closed enforcement;
 * this closes visibility -- where does a host still mint outside Vouch, and
 * where does the gate not reach.
 *
 * The command REPORTS. §10.6 settled that: --strict is opt-in, because an
 * unknown seam is something the static pass could not resolve, and failing on
 * those is noisy by design. That noise is the honest signal that static
 * analysis cannot prove runtime routing, so the tests below care most about
 * which findings are allowed to be silent -- none of them.
 */

function auditFixturePath(string $under = ''): string
{
    return dirname(__DIR__) . '/Support/Audit' . ($under === '' ? '' : '/' . $under);
}

/** @return array<string, mixed> */
function auditReport(): array
{
    Artisan::call('vouch:audit-tokens', ['--json' => true]);

    return jsonBody(Artisan::output());
}

/**
 * @param  array<string, mixed>  $report
 * @return list<array<string, mixed>>
 */
function auditSection(array $report, string $key): array
{
    $section = $report[$key] ?? null;

    if (! is_array($section)) {
        throw new RuntimeException("vouch:audit-tokens reported no {$key} section.");
    }

    /** @var list<array<string, mixed>> $section */
    return $section;
}

/**
 * Identifiers reported under one section.
 *
 * @param  array<string, mixed>  $report
 * @return list<string>
 */
function auditIdentifiers(array $report, string $key): array
{
    $found = array_map(
        static fn (array $row): string => stringValue($row['identifier'] ?? null),
        auditSection($report, $key),
    );

    sort($found);

    return $found;
}

beforeEach(function (): void {
    config(['vouch.audit.paths' => [auditFixturePath('app')]]);
    config(['vouch.audit.allowlist' => []]);
});

it('names every direct issuance site it can resolve', function (): void {
    $identifiers = auditIdentifiers(auditReport(), 'issuance_sites');

    expect($identifiers)->toContain('Vendor\Probe\DirectIssuer::mint')
        ->and($identifiers)->toContain('Vendor\Probe\DirectIssuer::mintFromLookup')
        ->and($identifiers)->toContain('Vendor\Probe\AllowlistedIssuer::mint');
});

it('does not report a mention of the call in a comment or a string', function (): void {
    /*
     * QuietFile names createToken( in a docblock, a line comment and a string
     * literal, and issues nothing. A scanner matching text rather than tokens
     * reports it -- and a report that cries wolf on prose is one an operator
     * learns to ignore, which costs more than the finding was worth.
     */
    $report = auditReport();

    $mentions = array_filter(
        array_merge(auditSection($report, 'issuance_sites'), auditSection($report, 'unknown_seams')),
        static fn (array $row): bool => str_contains(stringValue($row['file'] ?? null), 'QuietFile'),
    );

    expect($mentions)->toBe([]);
});

it('names each unresolvable construct rather than dropping it', function (): void {
    /*
     * The load-bearing property. A lexer cannot know whether
     * `$user->{$method}('api')` mints, and the wrong answer is to stay quiet:
     * the audit would report a clean surface it never understood.
     */
    $identifiers = auditIdentifiers(auditReport(), 'unknown_seams');

    expect($identifiers)->toContain('Vendor\Probe\DynamicIssuer::dynamicMethod')
        ->and($identifiers)->toContain('Vendor\Probe\DynamicIssuer::dynamicClass')
        ->and($identifiers)->toContain('Vendor\Probe\DynamicIssuer::indirect');
});

it('gives each unknown seam a reason', function (): void {
    // "Unresolved" without saying why leaves a host nothing to act on.
    foreach (auditSection(auditReport(), 'unknown_seams') as $seam) {
        expect(stringValue($seam['reason'] ?? null))->not->toBe('');
    }
});

it('names the roots it scanned', function (): void {
    /*
     * A clean report and an empty one look identical unless the command says
     * what it opened. This is the difference between "nothing mints outside
     * Vouch" and "I was pointed at a directory that does not exist".
     */
    $report = auditReport();

    expect(json_encode($report['scanned_paths'] ?? null))->toContain('Support/Audit/app');
});

it('reports a configured path it cannot scan as an unknown seam', function (): void {
    /*
     * NOT a silent skip. Reporting a clean audit of code it never opened is
     * the one outcome this command exists to prevent.
     */
    config(['vouch.audit.paths' => [auditFixturePath('app'), auditFixturePath('does-not-exist')]]);

    $seams = auditSection(auditReport(), 'unknown_seams');
    $unscannable = array_filter(
        $seams,
        static fn (array $row): bool => str_contains(stringValue($row['identifier'] ?? null), 'does-not-exist'),
    );

    expect($unscannable)->not->toBe([]);
});

it('silences an allowlisted site, and says it was silenced', function (): void {
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\AllowlistedIssuer::mint' => [
            'rationale' => 'Service tokens minted after an out-of-band review.',
            'owner' => 'platform-team',
        ],
    ]]);

    $report = auditReport();
    $allowlisted = array_filter(
        auditSection($report, 'issuance_sites'),
        static fn (array $row): bool => ($row['identifier'] ?? null) === 'Vendor\Probe\AllowlistedIssuer::mint',
    );

    // Silenced, not hidden: it keeps appearing, labelled.
    expect($allowlisted)->not->toBe([])
        ->and(stringValue(reset($allowlisted)['status'] ?? null))->toBe('allowlisted')
        ->and(Artisan::call('vouch:audit-tokens', ['--strict' => true]))->toBe(1);
});

it('refuses an allowlist entry with no rationale', function (): void {
    /*
     * The entry does NOT silence its seam. An allowlist is a record of a
     * decision, and an entry nobody will admit to is worth less than no entry
     * at all -- accepting it would convert the list from evidence into a mute
     * button.
     */
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\AllowlistedIssuer::mint' => ['owner' => 'platform-team'],
    ]]);

    $report = auditReport();
    $malformed = auditSection($report, 'allowlist_problems');

    expect(json_encode($malformed))->toContain('Vendor\Probe\AllowlistedIssuer::mint');

    $site = array_filter(
        auditSection($report, 'issuance_sites'),
        static fn (array $row): bool => ($row['identifier'] ?? null) === 'Vendor\Probe\AllowlistedIssuer::mint',
    );

    expect(stringValue(reset($site)['status'] ?? null))->toBe('reported');
});

it('refuses an allowlist entry with no owner', function (): void {
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\AllowlistedIssuer::mint' => ['rationale' => 'because'],
    ]]);

    expect(json_encode(auditSection(auditReport(), 'allowlist_problems')))
        ->toContain('Vendor\Probe\AllowlistedIssuer::mint');
});

it('accepts an optional review date without requiring one', function (): void {
    /*
     * `reviewed` is recorded where present and its absence is not a finding:
     * the required fields are the ones without which the entry means nothing.
     */
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\AllowlistedIssuer::mint' => [
            'rationale' => 'Service tokens minted after an out-of-band review.',
            'owner' => 'platform-team',
            'reviewed' => '2026-09-02',
        ],
    ]]);

    expect(auditSection(auditReport(), 'allowlist_problems'))->toBe([]);
});

it('reports an allowlist entry that matches nothing', function (): void {
    /*
     * A stale entry silences nothing, so it is harmless in the narrow sense --
     * and it misrepresents the shape of the codebase to the next reader, who
     * has no way to tell it from a live exemption. Removing it is the cheapest
     * fix there is.
     */
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\Deleted::mint' => ['rationale' => 'gone', 'owner' => 'platform-team'],
    ]]);

    expect(json_encode(auditSection(auditReport(), 'allowlist_problems')))
        ->toContain('Vendor\Probe\Deleted::mint');
});

it('reads enforcement coverage from the live router, not from source', function (): void {
    /*
     * Routes are registered by the time the command runs, so their middleware
     * can be enumerated exactly. Deriving them from source would reintroduce
     * guesswork the framework has already resolved.
     */
    Route::middleware(['api', 'vouch.token:aal2'])->post('/covered', fn (): string => 'ok');
    Route::middleware('api')->post('/uncovered', fn (): string => 'ok');

    $report = auditReport();
    $enforcement = $report['enforcement'] ?? null;

    expect(json_encode($enforcement))->toContain('/uncovered')
        ->and(json_encode($enforcement))->not->toContain('"/covered"');
});

it('reports and exits zero by default', function (): void {
    /*
     * Adopting the command must never break a host that has not opted in. The
     * findings are all present; only the exit code is withheld.
     */
    expect(Artisan::call('vouch:audit-tokens'))->toBe(0)
        ->and(Artisan::output())->toContain('DirectIssuer');
});

it('fails under strict on an unallowlisted site', function (): void {
    expect(Artisan::call('vouch:audit-tokens', ['--strict' => true]))->toBe(1);
});

it('fails under strict on an unknown seam alone', function (): void {
    /*
     * Isolated: the only file scanned is the dynamic one, so strict cannot be
     * failing on an issuance site. §10.6 is explicit that strict fails on what
     * the pass could not resolve, which is what makes it noisy on purpose.
     */
    config(['vouch.audit.paths' => [auditFixturePath('app/DynamicIssuer.php')]]);

    expect(auditIdentifiers(auditReport(), 'issuance_sites'))->toBe([])
        ->and(Artisan::call('vouch:audit-tokens', ['--strict' => true]))->toBe(1);
});

it('passes under strict when everything is resolved and accounted for', function (): void {
    /*
     * The green path has to exist, or --strict is a gate nobody can ever
     * satisfy and hosts will simply not run it.
     */
    config(['vouch.audit.paths' => [auditFixturePath('app/AllowlistedIssuer.php')]]);
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\AllowlistedIssuer::mint' => [
            'rationale' => 'Service tokens minted after an out-of-band review.',
            'owner' => 'platform-team',
        ],
    ]]);

    expect(Artisan::call('vouch:audit-tokens', ['--strict' => true]))->toBe(0);
});
