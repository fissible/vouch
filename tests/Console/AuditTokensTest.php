<?php

declare(strict_types=1);

use Fissible\Vouch\Console\CommandExit;
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

/**
 * One decoded row, matched by identifier, or null.
 *
 * Structural rather than a substring over encoded JSON. `json_encode()` escapes
 * `/` as `\/`, so a check for '/uncovered' can FAIL on a correct report, while
 * `not->toContain('"/covered"')` passes on a report that names /covered without
 * that exact quoting -- wrong in both directions at once.
 *
 * @param  array<string, mixed>  $report
 * @return array<string, mixed>|null
 */
function auditRow(array $report, string $key, string $identifier): ?array
{
    foreach (auditSection($report, $key) as $row) {
        if (($row['identifier'] ?? null) === $identifier) {
            return $row;
        }
    }

    return null;
}

/**
 * Findings that make --strict fail, so a green strict run can be shown to be
 * green for the right reason rather than by accident.
 *
 * @param  array<string, mixed>  $report
 * @return list<string>
 */
function auditBlockingFindings(array $report): array
{
    $blocking = array_map(
        static fn (array $row): string => stringValue($row['identifier'] ?? null),
        array_merge(
            array_filter(
                auditSection($report, 'issuance_sites'),
                static fn (array $row): bool => ($row['status'] ?? null) !== 'allowlisted',
            ),
            auditSection($report, 'unknown_seams'),
            auditSection($report, 'allowlist_problems'),
        ),
    );

    sort($blocking);

    return $blocking;
}

it('names every direct issuance site it can resolve', function (): void {
    $report = auditReport();

    expect(auditRow($report, 'issuance_sites', 'Vendor\Probe\DirectIssuer::mint'))->not->toBeNull()
        ->and(auditRow($report, 'issuance_sites', 'Vendor\Probe\DirectIssuer::mintFromLookup'))->not->toBeNull()
        ->and(auditRow($report, 'issuance_sites', 'Vendor\Probe\AllowlistedIssuer::mint'))->not->toBeNull();
});

it('finds issuance in a route file, not only in a class', function (): void {
    /*
     * Why the paths are configured rather than derived from autoload roots: a
     * closure route that mints directly is not reachable from a PSR-4 root, and
     * an audit that could not see it would report a clean surface while the
     * bypass sat in routes/api.php.
     */
    config(['vouch.audit.paths' => [auditFixturePath('routes')]]);

    $files = array_map(
        static fn (array $row): string => stringValue($row['file'] ?? null),
        auditSection(auditReport(), 'issuance_sites'),
    );

    // The specific file, not merely "a finding": a scanner reporting some
    // unrelated site would satisfy a non-empty check.
    expect(implode("\n", $files))->toContain('routes/api.php');
});

it('does not report a mention of the call in a comment, a string or a heredoc', function (): void {
    /*
     * QuietFile names createToken( in a docblock, a line comment, a string
     * literal and a heredoc, and issues nothing. A scanner matching text rather
     * than tokens reports it four times -- and a report that cries wolf on
     * prose is one an operator learns to ignore, which costs more than the
     * finding was worth.
     */
    $report = auditReport();

    foreach (['issuance_sites', 'unknown_seams'] as $key) {
        foreach (auditSection($report, $key) as $row) {
            expect(stringValue($row['file'] ?? null))->not->toContain('QuietFile')
                ->and(stringValue($row['identifier'] ?? null))->not->toContain('QuietFile');
        }
    }
});

it('names each unresolvable construct rather than dropping it', function (): void {
    /*
     * The load-bearing property. A lexer cannot know whether
     * `$user->{$method}('api')` mints, and the wrong answer is to stay quiet:
     * the audit would report a clean surface it never understood.
     */
    $report = auditReport();

    foreach ([
        'Vendor\Probe\DynamicIssuer::dynamicMethod',
        'Vendor\Probe\DynamicIssuer::dynamicClass',
        'Vendor\Probe\DynamicIssuer::indirect',
        'Vendor\Probe\DynamicIssuer::indirectArray',
    ] as $identifier) {
        expect(auditRow($report, 'unknown_seams', $identifier))->not->toBeNull("missing seam: {$identifier}");
    }
});

it('gives each unknown seam a reason, and there are seams to give one to', function (): void {
    /*
     * The count assertion is not padding. An earlier version looped over the
     * seams asserting each carried a reason, which passes perfectly on an empty
     * list -- the exact state a broken scanner produces.
     */
    $seams = auditSection(auditReport(), 'unknown_seams');

    expect(count($seams))->toBeGreaterThanOrEqual(4);

    foreach ($seams as $seam) {
        expect(stringValue($seam['reason'] ?? null))->not->toBe('');
    }
});

it('names the roots it scanned', function (): void {
    /*
     * A clean report and an empty one look identical unless the command says
     * what it opened. This is the difference between "nothing mints outside
     * Vouch" and "I was pointed at a directory that does not exist".
     */
    $scanned = auditReport()['scanned_paths'] ?? null;

    expect($scanned)->toBeArray()
        ->and($scanned)->toContain(auditFixturePath('app'));
});

it('reports a configured path it cannot scan as an unknown seam', function (): void {
    /*
     * NOT a silent skip. Reporting a clean audit of code it never opened is
     * the one outcome this command exists to prevent.
     */
    config(['vouch.audit.paths' => [auditFixturePath('app'), auditFixturePath('does-not-exist')]]);

    $report = auditReport();
    $unscannable = array_values(array_filter(
        auditSection($report, 'unknown_seams'),
        static fn (array $row): bool => str_contains(stringValue($row['identifier'] ?? null), 'does-not-exist'),
    ));

    expect($unscannable)->not->toBe([])
        ->and(stringValue($unscannable[0]['reason'] ?? null))->not->toBe('');
});

it('reports a configured path that escapes the base through a symlink', function (): void {
    /*
     * A scanned root is a claim about what was audited. A symlink pointing
     * outside it makes that claim false in a way nobody reading the config
     * would see, so the path is refused rather than followed.
     */
    $base = sys_get_temp_dir() . '/vouch-audit-' . bin2hex(random_bytes(4));
    $outside = $base . '/outside';
    $root = $base . '/root';
    mkdir($outside, 0o755, true);
    mkdir($root, 0o755, true);
    file_put_contents($outside . '/Hidden.php', "<?php\n");
    symlink($outside, $root . '/link');

    config(['vouch.audit.paths' => [$root]]);

    try {
        $escaped = array_values(array_filter(
            auditSection(auditReport(), 'unknown_seams'),
            static fn (array $row): bool => str_contains(stringValue($row['identifier'] ?? null), 'link'),
        ));

        expect($escaped)->not->toBe([])
            // "Named with its reason" is the guarantee; a generic seam with an
            // empty reason satisfies the count and tells a host nothing.
            ->and(stringValue($escaped[0]['reason'] ?? null))->not->toBe('');
    } finally {
        @unlink($root . '/link');
        @unlink($outside . '/Hidden.php');
        @rmdir($root);
        @rmdir($outside);
        @rmdir($base);
    }
});

it('reports an unreadable path rather than skipping it', function (): void {
    $base = sys_get_temp_dir() . '/vouch-audit-' . bin2hex(random_bytes(4));
    mkdir($base, 0o755, true);
    $locked = $base . '/locked';
    mkdir($locked, 0o755, true);
    chmod($locked, 0o000);

    config(['vouch.audit.paths' => [$locked]]);

    try {
        $named = array_values(array_filter(
            auditSection(auditReport(), 'unknown_seams'),
            static fn (array $row): bool => str_contains(stringValue($row['identifier'] ?? null), 'locked'),
        ));

        // The seam must NAME the path it could not read. Any fabricated seam
        // with a non-empty reason satisfied the previous form.
        expect($named)->not->toBe([])
            ->and(stringValue($named[0]['reason'] ?? null))->not->toBe('');
    } finally {
        chmod($locked, 0o755);
        @rmdir($locked);
        @rmdir($base);
    }
})->skip(
    // NOT a static closure: Pest binds the predicate to the test instance and
    // a static one throws "Cannot bind an instance to a static closure" -- the
    // test then errors on the harness rather than running at all.
    fn (): bool => function_exists('posix_geteuid') && posix_geteuid() === 0,
    'runs as root, where an unreadable directory cannot be constructed',
);

it('silences an allowlisted site, and says it was silenced', function (): void {
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\AllowlistedIssuer::mint' => [
            'rationale' => 'Service tokens minted after an out-of-band review.',
            'owner' => 'platform-team',
        ],
    ]]);

    $row = auditRow(auditReport(), 'issuance_sites', 'Vendor\Probe\AllowlistedIssuer::mint');

    // Silenced, not hidden: it keeps appearing, labelled.
    expect($row)->not->toBeNull()
        ->and(stringValue($row['status'] ?? null))->toBe('allowlisted');
});

it('records a review date when one is supplied', function (): void {
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\AllowlistedIssuer::mint' => [
            'rationale' => 'Service tokens minted after an out-of-band review.',
            'owner' => 'platform-team',
            'reviewed' => '2026-09-02',
        ],
    ]]);

    $report = auditReport();

    // The exact field on the exact row. An encoded-blob check passes on any
    // unrelated occurrence of the date anywhere in the report.
    expect(auditSection($report, 'allowlist_problems'))->toBe([])
        ->and(stringValue(auditRow($report, 'issuance_sites', 'Vendor\Probe\AllowlistedIssuer::mint')['reviewed'] ?? null))
        ->toBe('2026-09-02');
});

it('refuses an allowlist entry with no rationale, and keeps reporting its seam', function (): void {
    /*
     * The entry does NOT silence its seam. An allowlist is a record of a
     * decision, and an entry nobody will admit to is worth less than no entry
     * at all -- accepting it would turn the list from evidence into a mute
     * button.
     */
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\AllowlistedIssuer::mint' => ['owner' => 'platform-team'],
    ]]);

    $report = auditReport();

    expect(auditRow($report, 'allowlist_problems', 'Vendor\Probe\AllowlistedIssuer::mint'))->not->toBeNull()
        ->and(stringValue(auditRow($report, 'issuance_sites', 'Vendor\Probe\AllowlistedIssuer::mint')['status'] ?? null))
        ->toBe('reported');
});

it('refuses an allowlist entry with no owner, and keeps reporting its seam', function (): void {
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\AllowlistedIssuer::mint' => ['rationale' => 'because'],
    ]]);

    $report = auditReport();

    expect(auditRow($report, 'allowlist_problems', 'Vendor\Probe\AllowlistedIssuer::mint'))->not->toBeNull()
        ->and(stringValue(auditRow($report, 'issuance_sites', 'Vendor\Probe\AllowlistedIssuer::mint')['status'] ?? null))
        ->toBe('reported');
});

it('reports an allowlist entry that matches nothing', function (): void {
    /*
     * A stale entry silences nothing, so it is harmless in the narrow sense --
     * and it misrepresents the shape of the codebase to the next reader, who
     * cannot tell it from a live exemption. Removing it is the cheapest fix
     * there is.
     */
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\Deleted::mint' => ['rationale' => 'gone', 'owner' => 'platform-team'],
    ]]);

    expect(auditRow(auditReport(), 'allowlist_problems', 'Vendor\Probe\Deleted::mint'))->not->toBeNull();
});

it('reads enforcement coverage from the live router, not from source', function (): void {
    /*
     * Routes are registered by the time the command runs, so their middleware
     * can be enumerated exactly. Deriving them from source would reintroduce
     * guesswork the framework has already resolved.
     */
    Route::middleware(['api', 'vouch.token:aal2'])->post('/covered', fn (): string => 'ok');
    Route::middleware('api')->post('/uncovered', fn (): string => 'ok');

    $uris = array_map(
        static fn (array $row): string => stringValue($row['uri'] ?? null),
        auditSection(auditReport(), 'uncovered_routes'),
    );

    expect($uris)->toContain('uncovered')
        ->and($uris)->not->toContain('covered');
});

it('expands a middleware group the host defined itself', function (): void {
    /*
     * The reason enforcement reads the router rather than the route: a host
     * group carries the gate for every route inside it, and matching literal
     * route middleware would report all of them uncovered.
     */
    app('router')->middlewareGroup('host.assured', ['api', 'vouch.token:aal2']);

    Route::middleware('host.assured')->post('/group-covered', fn (): string => 'ok');
    Route::middleware('api')->post('/group-uncovered', fn (): string => 'ok');

    $uris = array_map(
        static fn (array $row): string => stringValue($row['uri'] ?? null),
        auditSection(auditReport(), 'uncovered_routes'),
    );

    expect($uris)->toContain('group-uncovered')
        ->and($uris)->not->toContain('group-covered');
});

it('reports and exits zero by default', function (): void {
    /*
     * Adopting the command must never break a host that has not opted in. The
     * findings are all present; only the exit code is withheld.
     */
    expect(Artisan::call('vouch:audit-tokens'))->toBe(CommandExit::Success->value)
        ->and(Artisan::output())->toContain('DirectIssuer');
});

it('does not fail under strict on an uncovered route', function (): void {
    /*
     * The one finding surfaced without ever blocking on it. Most routes should
     * not carry the token gate, and the command cannot know which ought to --
     * that judgement needs the host's intent, which nothing in the report
     * holds. Failing here would make --strict unusable for any application
     * with a public endpoint.
     */
    config(['vouch.audit.paths' => [auditFixturePath('app/AllowlistedIssuer.php')]]);
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\AllowlistedIssuer::mint' => [
            'rationale' => 'Service tokens minted after an out-of-band review.',
            'owner' => 'platform-team',
        ],
    ]]);

    Route::middleware('api')->post('/wide-open', fn (): string => 'ok');

    $report = auditReport();
    $uris = array_map(
        static fn (array $row): string => stringValue($row['uri'] ?? null),
        auditSection($report, 'uncovered_routes'),
    );

    expect($uris)->toContain('wide-open')
        ->and(auditBlockingFindings($report))->toBe([])
        ->and(Artisan::call('vouch:audit-tokens', ['--strict' => true]))->toBe(CommandExit::Success->value);
});

it('exits the same way in json mode as in the human rendering', function (): void {
    /*
     * auditReport() discards the exit code, so every other test in this file is
     * blind to it: --json could return failure by default while the table
     * rendering returns zero, and nothing here would notice.
     */
    expect(Artisan::call('vouch:audit-tokens', ['--json' => true]))->toBe(CommandExit::Success->value)
        ->and(Artisan::call('vouch:audit-tokens'))->toBe(CommandExit::Success->value);

    config(['vouch.audit.paths' => [auditFixturePath('app/DirectIssuer.php')]]);

    expect(Artisan::call('vouch:audit-tokens', ['--json' => true, '--strict' => true]))->toBe(CommandExit::Failure->value)
        ->and(Artisan::call('vouch:audit-tokens', ['--strict' => true]))->toBe(CommandExit::Failure->value);
});

it('fails under strict on an unallowlisted site alone', function (): void {
    /*
     * Isolated to a file with no dynamic constructs, so strict cannot be
     * failing on an unknown seam. Every strict assertion below states the ONE
     * condition it is about and proves the others are absent -- a strict test
     * failing for an unrelated reason has been the most common defect in this
     * suite.
     */
    config(['vouch.audit.paths' => [auditFixturePath('app/DirectIssuer.php')]]);

    $report = auditReport();

    expect(auditSection($report, 'unknown_seams'))->toBe([])
        ->and(auditSection($report, 'allowlist_problems'))->toBe([])
        ->and(Artisan::call('vouch:audit-tokens', ['--strict' => true]))->toBe(CommandExit::Failure->value);
});

it('fails under strict on an unknown seam alone', function (): void {
    config(['vouch.audit.paths' => [auditFixturePath('app/DynamicIssuer.php')]]);

    $report = auditReport();

    expect(auditSection($report, 'issuance_sites'))->toBe([])
        ->and(auditSection($report, 'allowlist_problems'))->toBe([])
        ->and(Artisan::call('vouch:audit-tokens', ['--strict' => true]))->toBe(CommandExit::Failure->value);
});

it('fails under strict on a malformed allowlist entry, with both blockers named', function (): void {
    /*
     * This one CANNOT be isolated, and pretending otherwise would be the
     * mistake. A malformed entry deliberately fails to silence its seam, so
     * two blockers exist by design: the entry and the site it did not cover.
     * Both are asserted, so the failure is pinned to a state rather than to a
     * count.
     */
    config(['vouch.audit.paths' => [auditFixturePath('app/AllowlistedIssuer.php')]]);
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\AllowlistedIssuer::mint' => ['rationale' => 'no owner given'],
    ]]);

    $report = auditReport();

    expect(auditSection($report, 'unknown_seams'))->toBe([])
        ->and(auditRow($report, 'allowlist_problems', 'Vendor\Probe\AllowlistedIssuer::mint'))->not->toBeNull()
        ->and(stringValue(auditRow($report, 'issuance_sites', 'Vendor\Probe\AllowlistedIssuer::mint')['status'] ?? null))
        ->toBe('reported')
        ->and(Artisan::call('vouch:audit-tokens', ['--strict' => true]))->toBe(CommandExit::Failure->value);
});

it('fails under strict on a stale allowlist entry alone', function (): void {
    config(['vouch.audit.paths' => [auditFixturePath('app/AllowlistedIssuer.php')]]);
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\AllowlistedIssuer::mint' => [
            'rationale' => 'Service tokens minted after an out-of-band review.',
            'owner' => 'platform-team',
        ],
        'Vendor\Probe\Deleted::mint' => ['rationale' => 'gone', 'owner' => 'platform-team'],
    ]]);

    $report = auditReport();

    /*
     * The stale entry is the ONLY blocker: the live exemption must still be
     * honoured. Without that assertion an implementation could ignore staleness
     * entirely, report the valid site instead, and still fail strict -- passing
     * this test for the opposite reason.
     */
    expect(auditSection($report, 'unknown_seams'))->toBe([])
        ->and(auditRow($report, 'allowlist_problems', 'Vendor\Probe\Deleted::mint'))->not->toBeNull()
        ->and(stringValue(auditRow($report, 'issuance_sites', 'Vendor\Probe\AllowlistedIssuer::mint')['status'] ?? null))
        ->toBe('allowlisted')
        ->and(Artisan::call('vouch:audit-tokens', ['--strict' => true]))->toBe(CommandExit::Failure->value);
});

it('fails under strict on an unscannable path alone', function (): void {
    config(['vouch.audit.paths' => [auditFixturePath('does-not-exist')]]);

    $report = auditReport();
    $unscannable = array_values(array_filter(
        auditSection($report, 'unknown_seams'),
        static fn (array $row): bool => str_contains(stringValue($row['identifier'] ?? null), 'does-not-exist'),
    ));

    /*
     * The POSITIVE blocker, asserted before the exit code. Proving only that
     * the other sections are empty leaves a command that fails strict
     * unconditionally passing this test.
     */
    expect($unscannable)->not->toBe([])
        ->and(auditSection($report, 'issuance_sites'))->toBe([])
        ->and(auditSection($report, 'allowlist_problems'))->toBe([])
        ->and(Artisan::call('vouch:audit-tokens', ['--strict' => true]))->toBe(CommandExit::Failure->value);
});

it('passes under strict when everything is resolved and accounted for', function (): void {
    /*
     * The green path has to exist, or --strict is a gate nobody can satisfy and
     * hosts will simply not run it. The blocking-findings assertion is what
     * makes the zero meaningful: an exit code alone cannot distinguish "clean"
     * from "found nothing because it scanned nothing".
     */
    config(['vouch.audit.paths' => [auditFixturePath('app/AllowlistedIssuer.php')]]);
    config(['vouch.audit.allowlist' => [
        'Vendor\Probe\AllowlistedIssuer::mint' => [
            'rationale' => 'Service tokens minted after an out-of-band review.',
            'owner' => 'platform-team',
        ],
    ]]);

    $report = auditReport();

    expect(auditBlockingFindings($report))->toBe([])
        ->and(auditRow($report, 'issuance_sites', 'Vendor\Probe\AllowlistedIssuer::mint'))->not->toBeNull()
        ->and(Artisan::call('vouch:audit-tokens', ['--strict' => true]))->toBe(CommandExit::Success->value);
});
