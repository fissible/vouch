<?php

declare(strict_types=1);

use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Artisan;

/*
 * Task 7 is positioning, and positioning is a claim about PLACEMENT: a reader
 * who never scrolls has to already know what Vouch does not do.
 *
 * Documentation under test has a failure mode code does not — an assertion on
 * a bare word rewards dropping the word in rather than explaining the thing.
 * So nothing here checks for a term in the document at large. Every boundary
 * is asserted as CO-OCCURRENCE within one block: the actionable identifier
 * has to sit in the same paragraph, list or code fence as the condition it
 * applies to. That is an automatable floor, not a substitute for reading the
 * result; whether the prose is any good stays a human judgement.
 *
 * The rest is a doc-rot guard. Every Vouch identifier the README names in
 * backticks must resolve against the running package, so renaming a middleware
 * alias or a config key breaks CI instead of quietly making the front page
 * wrong.
 */

/**
 * Everything before the first `##`.
 *
 * A Markdown structure boundary rather than a line count: a line budget is
 * defeated by a wrapped paragraph, a code fence or a badge row, and it means
 * nothing on the two renderings that matter — Packagist and a phone.
 */
function readmeLead(): string
{
    return explode("\n## ", readmeContents(), 2)[0];
}

/**
 * Blocks of the README. See docBlocks() in tests/Pest.php for the splitting
 * rules and why they are what they are.
 *
 * @return list<string>
 */
function readmeBlocks(string $markdown): array
{
    return docBlocks($markdown);
}

/**
 * Is there ONE README block matching all of these patterns?
 *
 * @param  list<string>  $patterns
 */
function readmeExplainsTogetherMatching(array $patterns, ?string $within = null): bool
{
    return docExplainsTogether($patterns, $within ?? readmeContents());
}

/**
 * The arguments of every `composer require` in the document.
 *
 * Matched across the whole command rather than line by line, following a
 * trailing-backslash continuation to its end: a `composer require \` split
 * across lines, or two spaces between the words, walks straight past a
 * single-line regex, and a fixed-width window misses a long package list.
 *
 * @return list<string>
 */
function readmeComposerRequireArguments(?string $within = null): array
{
    /*
     * The continuation alternative comes FIRST. With `[^\n]` leading, it
     * consumes the backslash itself, the newline then matches neither branch,
     * and the match stops one character before the package that mattered.
     */
    preg_match_all('/composer\s+require\b((?:\\\\\n|[^\n])*)/i', $within ?? readmeContents(), $matches);

    /** @var list<string> $arguments */
    $arguments = $matches[1];

    return $arguments;
}

/**
 * Fences that show an actual route, not a commented fragment.
 *
 * A recipe is only worth anything if it can be copied. `permission:` inside a
 * `//` comment is prose in a code font — it demonstrates nothing and cannot be
 * pasted. Both halves must appear on lines that are not comments, though not
 * necessarily the same line, because a route is routinely written across two.
 *
 * @return list<string>
 */
function readmeRouteFences(?string $within = null): array
{
    return array_values(array_filter(readmeFences($within), static function (string $fence): bool {
        $ability = false;
        $registration = false;

        foreach (explode("\n", readmeUncommented($fence)) as $line) {
            if (trim($line) === '') {
                continue;
            }

            $ability = $ability || str_contains($line, 'permission:');
            $registration = $registration || preg_match('/Route::|->middleware\(/', $line) === 1;
        }

        return $ability && $registration;
    }));
}

/**
 * The body of an `assurance_requirements` map inside a fence, if it has one.
 *
 * Returning the body rather than the whole fence is what stops an unrelated
 * `'ability' => 'aal2'` pair elsewhere in the same block from standing in for
 * an entry that is actually in the map.
 */
function readmeAbilityMapBody(string $fence): ?string
{
    if (preg_match('/assurance_requirements\W{0,8}\[(.*?)\]/s', readmeUncommented($fence), $matches) !== 1) {
        return null;
    }

    return $matches[1];
}

/**
 * The `##` section that shows the composition — the one whose fences mention
 * `permission:`. Proximity is part of the claim: a route fragment and a config
 * fragment in different parts of the document are two fragments, not one
 * worked example.
 */
function readmeCompositionSection(?string $within = null): string
{
    foreach (preg_split('/\n(?=## )/', $within ?? readmeContents()) ?: [] as $section) {
        if (readmeRouteFences($section) !== []) {
            return $section;
        }
    }

    return '';
}

/**
 * Every inline-code span, which is where a document puts an identifier.
 *
 * Scanning only backticked spans keeps prose that happens to contain a dotted
 * phrase out of the identifier checks, and makes "write identifiers as code"
 * an enforced convention rather than a preference.
 *
 * @return list<string>
 */
function readmeCodeSpans(): array
{
    preg_match_all('/(?<!`)`([^`\n]+)`(?!`)/', readmeContents(), $matches);

    /** @var list<string> $spans */
    $spans = array_values(array_unique($matches[1]));

    return $spans;
}

it('exists', function (): void {
    expect(is_file(readmePath()))->toBeTrue();
});

it('opens by naming the package', function (): void {
    expect(readmeContents())->toStartWith('# Vouch');
});

it('defines what vouch actually does before the first section', function (): void {
    /*
     * A positive definition, not just the word "authentication". Naming the
     * concrete mechanisms is what stops the lead from being a slogan — and
     * they are the thing a reader is scanning for when deciding whether this
     * package is the one they need.
     */
    $lead = strtolower(readmeLead());
    $mechanisms = array_filter(
        ['password', 'otp', 'mfa', 'sso', 'passkey'],
        static fn (string $mechanism): bool => str_contains($lead, $mechanism),
    );

    expect($lead)->toContain('authentication')
        ->and(count($mechanisms))->toBeGreaterThanOrEqual(2);
});

it('lists all three non-goals together, above the fold', function (): void {
    /*
     * One block, before the first `##`. Three non-goals scattered through the
     * lead are three words; together they are a statement of scope, and a
     * reader who stops after one screen must not leave thinking this package
     * does authorization. That misunderstanding is what produces `permission:`
     * routes with no assurance requirement — the gap Task 5b exists to close.
     */
    expect(readmeExplainsTogetherMatching(
        ['/\bauthorization\b/i', '/\btokens?\b/i', '/\bUI\b|\buser interface\b/i'],
        readmeLead(),
    ))->toBeTrue();
});

/*
 * The composition. Task 6's recipe is the positioning made concrete: Vouch
 * proves the assurance, the host's own package decides the permission.
 */

it('shows a real route composed with a host authorization package', function (): void {
    /*
     * A fence that merely contains the string `permission:` could be a comment
     * or a fragment. The recipe is only useful if it is a route registration a
     * reader can copy, so the fence has to look like one.
     */
    expect(readmeRouteFences())->not->toBeEmpty();
});

it('shows the ability map that makes the composition safe', function (): void {
    /*
     * An ability keyed to a level INSIDE the map, not a bare mention of the
     * config key and a level floating somewhere in the same fence: a reader
     * has to be able to copy the shape, and the shape is the pair.
     */
    $mapped = array_filter(
        array_map(readmeAbilityMapBody(...), readmeFences()),
        static fn (?string $body): bool => $body !== null
            && preg_match("/'[A-Za-z0-9._-]+'\s*=>\s*'aal[0-3]'/", $body) === 1,
    );

    expect($mapped)->not->toBeEmpty();
});

it('makes the route and the map ONE worked example, not two unrelated ones', function (): void {
    /*
     * The route fence and the config fence are deliberately separate — a route
     * registration and a config array do not belong in one block — but they
     * have to be about the same ability, or the reader is shown two fragments
     * and left to guess how they connect. That connection is the entire point:
     * the route names the permission, the map supplies the assurance, and
     * neither mentions the other.
     */
    $routed = [];
    $mapped = [];

    /*
     * Scoped to the section that shows the composition, so two unrelated
     * examples in different parts of the document cannot satisfy each other.
     */
    $section = readmeCompositionSection();

    foreach (readmeRouteFences($section) as $fence) {
        preg_match_all('/permission:([A-Za-z0-9._-]+)/', $fence, $routes);

        foreach ($routes[1] as $ability) {
            foreach (explode('|', $ability) as $alternative) {
                $routed[] = $alternative;
            }
        }
    }

    foreach (readmeFences($section) as $fence) {
        $body = readmeAbilityMapBody($fence);

        if ($body !== null) {
            preg_match_all("/'([A-Za-z0-9._-]+)'\s*=>\s*'aal[0-3]'/", $body, $keys);
            $mapped = [...$mapped, ...$keys[1]];
        }
    }

    expect(array_intersect($routed, $mapped))->not->toBeEmpty();
});

/*
 * The four boundaries PROJECT.md records as owed to these tasks. Each is
 * asserted as the identifier a host needs in order to ACT, co-located with the
 * condition that makes it matter. A reader who cannot name the alias, the
 * report field or the config key cannot do anything about the boundary.
 */

it('explains that only the web and api groups are covered, and how to cover another', function (): void {
    expect(readmeExplainsTogetherMatching(
        ['/`?vouch\.ability`?/', '/\bweb\b/', '/\bapi\b/', '/\bonly\b|\bnot\b|\bother\b|\bcustom\b/i'],
    ))->toBeTrue();
});

it('explains how a host checks which groups are actually enforced', function (): void {
    expect(readmeExplainsTogetherMatching(['/enforced_groups/', '/vouch:assurance-map/']))->toBeTrue();
});

it('explains that the gate hook alone is not enforcement', function (): void {
    /*
     * The survey's central finding, and the reason the middleware exists. A
     * host that believes the Gate hook is the mechanism will assume a
     * controller-side check is covered when an earlier grant bypasses it.
     */
    expect(readmeExplainsTogetherMatching(
        ['/\bGate\b/', '/middleware/i', '/\bgrants?\b/i', '/\bnot\b|\bbypass|\balone\b|\bcannot\b/i'],
    ))->toBeTrue();
});

it('explains what a request with no vouch session gets, until 2.4', function (): void {
    /*
     * Boundary two. 5b does not inspect a bearer token — it refuses an
     * AUTHENTICATED request that carries no Vouch session, with a stated 403,
     * rather than failing open. A host running a token API needs to know that
     * before it maps an ability, not after.
     */
    expect(readmeExplainsTogetherMatching(
        ['/\b403\b/', '/insufficient_assurance/', '/\bsession\b/i', '/\b2\.4\b/'],
    ))->toBeTrue();
});

it('explains that strict mode cannot use gate definitions', function (): void {
    // `Gate::abilities()` is empty at boot, which is why the declared list is
    // the only source strict mode can answer to. Without the reason, being
    // told to duplicate a list reads as busywork.
    expect(readmeExplainsTogetherMatching(
        ['/declared_abilities/', '/Gate::abilities\(\)/', '/\bboot\b/i', '/\bempty\b|\bnothing\b|\bnot\b/i'],
    ))->toBeTrue();
});

it('explains the can() takeover and that the command reports it', function (): void {
    // Detectable: the command compares where can()'s body comes from, so it
    // catches any replacement, Bouncer's trait included.
    expect(readmeExplainsTogetherMatching(
        ['/can\(\)/', '/user_model_routes_to_gate/', '/vouch:assurance-map/'],
    ))->toBeTrue();
});

it('explains the bouncer slot switch, which vouch cannot detect at all', function (): void {
    // NOT detectable, unlike the can() takeover above. runBeforePolicies()
    // moves Bouncer's grant ahead of a deny-only hook, and nothing in Vouch
    // can see it — so the README is the only place a host learns it matters.
    expect(readmeExplainsTogetherMatching(
        ['/runBeforePolicies/', '/Bouncer/i', '/\bcannot\b|\bcan not\b|\bno way\b|\bnot detect/i'],
    ))->toBeTrue();
});

it('has no composer require line naming an authorization package', function (): void {
    /*
     * Task 6's decision, enforced where a reader would actually be misled. A
     * `composer require` line naming an authorization package reads as a
     * prerequisite no matter what the surrounding sentence says.
     */
    $offenders = array_values(array_filter(
        readmeComposerRequireArguments(),
        static fn (string $arguments): bool => preg_match('/spatie|bouncer/i', $arguments) === 1,
    ));

    expect($offenders)->toBe([]);
});

/*
 * Doc-rot guards.
 */

it('names only artisan commands that are actually registered', function (): void {
    preg_match_all('/\bvouch:[a-z][a-z-]*(?::[a-z][a-z-]*)*/', readmeContents(), $matches);

    $unknown = array_values(array_diff(array_unique($matches[0]), array_keys(Artisan::all())));

    expect($unknown)->toBe([]);
});

it('names only middleware aliases and config keys that resolve', function (): void {
    /*
     * Fenced examples are scanned as well as inline spans, because the fences
     * are where the copyable recipe lives — a misspelled config key there is
     * the doc rot that actually costs someone an afternoon, and it would sail
     * past a guard that only read the prose.
     */
    preg_match_all('/vouch\.[a-z_]+(?:\.[a-z_]+)*/', implode("\n", readmeFences()), $inFences);

    $candidates = array_unique([...readmeCodeSpans(), ...$inFences[0]]);
    $unknown = [];

    foreach ($candidates as $candidate) {
        if (preg_match('/^vouch\.[a-z_]+(\.[a-z_]+)*(:[A-Za-z0-9,._-]+)?$/', $candidate) !== 1) {
            continue;
        }

        // A middleware alias may carry a parameter (`vouch.assurance:aal2`);
        // the parameter is not part of the name being resolved.
        $base = explode(':', $candidate, 2)[0];

        if (array_key_exists($base, app(Router::class)->getMiddleware()) || config()->has($base)) {
            continue;
        }

        $unknown[] = $candidate;
    }

    expect($unknown)->toBe([]);
});

it('names enough of the surface that the two guards above mean something', function (): void {
    /*
     * Both guards are satisfied by a README that mentions no identifier at
     * all. This is what makes them bite: the document has to actually name the
     * surface it claims to document.
     */
    $identifiers = array_filter(
        readmeCodeSpans(),
        static fn (string $span): bool => str_starts_with($span, 'vouch.') || str_contains($span, 'vouch:'),
    );

    expect(count($identifiers))->toBeGreaterThanOrEqual(6);
});

/*
 * readmeBlocks() is the load-bearing helper — every boundary assertion above
 * is only as meaningful as its splitting. These fixtures pin the two
 * behaviours that were established by hand and would otherwise silently
 * regress: prose is never joined to the list that follows it, and a bullet is
 * never separated from its own indented continuation.
 */

it('separates an introduction from the list that follows it', function (): void {
    // Otherwise a fact in the intro and a fact in a bullet count as explained
    // together, which is the token stuffing the block split exists to stop.
    $blocks = readmeBlocks("Intro sentence:\n- first bullet\n- second bullet");

    expect($blocks)->toBe(['Intro sentence:', '- first bullet', '- second bullet']);
});

it('separates an introduction from a list even across a blank line', function (): void {
    $blocks = readmeBlocks("Intro sentence:\n\n- first bullet\n- second bullet");

    expect($blocks)->toBe(['Intro sentence:', '- first bullet', '- second bullet']);
});

it('keeps a list item together with its indented continuation', function (): void {
    // The opposite failure: splitting these would fail an assertion the item
    // genuinely satisfies, and the only way to pass would be to cram the
    // explanation onto one line.
    $blocks = readmeBlocks("- bullet\n\n  continued explanation");

    expect($blocks)->toHaveCount(1)
        ->and($blocks[0])->toContain('bullet')
        ->and($blocks[0])->toContain('continued explanation');
});

it('keeps a fenced block whole rather than splitting it into paragraphs', function (): void {
    $blocks = readmeBlocks("Before.\n\n```php\n\$a = 1;\n\n\$b = 2;\n```\n\nAfter.");

    expect($blocks)->toHaveCount(3)
        ->and($blocks[1])->toContain('$a = 1;')
        ->and($blocks[1])->toContain('$b = 2;');
});

it('follows a backslash-continued composer require to its end', function (): void {
    // A fixed window or a line-based match would stop before the package that
    // actually matters, and the guard would report a clean document.
    $arguments = readmeComposerRequireArguments("composer require fissible/vouch \\\n    spatie/laravel-permission\n");

    expect($arguments)->toHaveCount(1)
        ->and($arguments[0])->toContain('spatie/laravel-permission');
});

it('reads a long composer require argument list in full', function (): void {
    $tail = str_repeat('vendor/filler ', 40) . 'silber/bouncer';

    expect(readmeComposerRequireArguments('composer  require ' . $tail)[0] ?? '')
        ->toContain('silber/bouncer');
});

it('scopes the composition section to the one that shows the route', function (): void {
    /*
     * Pins the proximity rule. Without it, widening the helper to return the
     * whole document would still pass against a well-formed README, and two
     * unrelated examples in different sections would silently count as one.
     */
    $markdown = "## Install\n\n```php\n// nothing here\n```\n\n"
        . "## Composition\n\n```php\nRoute::post('/x')->middleware('permission:invoices.approve');\n```\n\n"
        . "## Elsewhere\n\n```php\n'assurance_requirements' => ['invoices.approve' => 'aal2'],\n```\n";

    $section = readmeCompositionSection($markdown);

    expect($section)->toContain('## Composition')
        ->and($section)->not->toContain('assurance_requirements');
});

it('reads a tilde fenced example as a fence', function (): void {
    // GitHub renders `~~~` identically; an example written that way must not
    // fall outside the doc-rot and composition scans.
    expect(readmeFences("~~~php\nRoute::post('/x')->middleware('permission:a');\n~~~"))->toHaveCount(1);
});

it('does not count a commented-out route as a copyable example', function (): void {
    // `permission:` inside a comment is prose in a code font. It demonstrates
    // nothing and cannot be pasted, so it must not satisfy the recipe.
    expect(readmeRouteFences("```php\n// Route::post('/x')->middleware('permission:a');\n```"))->toBe([]);
});

it('counts a route written across two lines', function (): void {
    // The predicate asks for both halves on non-comment lines, not on the
    // same line: a route with a fluent ->middleware() on its own line is the
    // normal way to write this.
    $fence = "```php\nRoute::post('/invoices/{id}/approve', ApproveController::class)\n"
        . "    ->middleware(['permission:invoices.approve']);\n```";

    expect(readmeRouteFences($fence))->toHaveCount(1);
});

it('reads ability keys only from inside the assurance map', function (): void {
    // A pair sitting next to the map, rather than in it, is not an entry.
    $fence = "```php\n'assurance_requirements' => [\n    'invoices.approve' => 'aal2',\n],\n"
        . "'something_else' => ['decoy.ability' => 'aal3'],\n```";

    $body = readmeAbilityMapBody($fence);

    expect($body)->toContain('invoices.approve')
        ->and($body)->not->toContain('decoy.ability');
});

it('keeps a tilde fenced block whole when splitting into blocks', function (): void {
    $blocks = readmeBlocks("Before.\n\n~~~php\n\$a = 1;\n\n\$b = 2;\n~~~\n\nAfter.");

    expect($blocks)->toHaveCount(3)
        ->and($blocks[1])->toContain('$a = 1;')
        ->and($blocks[1])->toContain('$b = 2;');
});

it('does not count a block-commented route as a copyable example', function (): void {
    // The interior lines of a `/* ... */` carry no marker of their own, so a
    // line-by-line scan would read them as live code.
    $fence = "```php\n/*\nRoute::post('/x')->middleware('permission:a');\n*/\n```";

    expect(readmeRouteFences($fence))->toBe([]);
});

it('does not count a commented-out ability map as a shown map', function (): void {
    // Symmetric with the route predicate: a map that is commented out shows
    // nothing and cannot be pasted.
    $fence = "```php\n// 'assurance_requirements' => ['invoices.approve' => 'aal2'],\n```";

    expect(readmeAbilityMapBody($fence))->toBeNull();
});

it('still reads a live ability map', function (): void {
    // The pair for the fixture above: stripping comments must not strip code.
    $fence = "```php\n'assurance_requirements' => [\n    'invoices.approve' => 'aal2',\n],\n```";

    expect(readmeAbilityMapBody($fence))->toContain("'invoices.approve' => 'aal2'");
});
