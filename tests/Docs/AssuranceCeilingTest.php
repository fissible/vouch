<?php

declare(strict_types=1);

/*
 * Issue #7 — the two facts a host cannot discover by reading the code it writes.
 *
 * Both are silent. A route requiring aal3 fails closed forever and looks like a
 * working route; a morph-map change invalidates every stored subject key and
 * looks like a routine refactor. Neither produces an error, so documentation is
 * the only control there is.
 *
 * Asserted as CO-OCCURRENCE within one block, following ReadmePositioningTest:
 * an assertion on a bare word rewards dropping the word in rather than
 * explaining the thing. Naming `aal3`, `aal2` and the vocabulary in one
 * paragraph is not the claim -- the claim is that the one CAPS at the other,
 * and why -- so each rule below requires the load-bearing term as well as the
 * subject it applies to.
 */

function operationsContents(): string
{
    $raw = @file_get_contents(dirname(__DIR__, 2) . '/docs/operations.md');

    if ($raw === false) {
        throw new RuntimeException('docs/operations.md does not exist.');
    }

    return $raw;
}

/**
 * Is there ONE block, in the README or in operations, matching all of these?
 *
 * Used for the morph-map warning only. The aal3 rules are README-only: the
 * ability map a host copies and the `vouch.assurance` alias both live there, so
 * an explanation that exists only in operations leaves the dangerous surface
 * unexplained at the point of use.
 *
 * @param  list<string>  $patterns
 */
function hostDocsExplainTogether(array $patterns): bool
{
    return docExplainsTogether($patterns, readmeContents())
        || docExplainsTogether($patterns, operationsContents());
}

it('states that the shipped vocabulary caps at aal2, and why', function (): void {
    /*
     * The scope and the cause together. "Vouch cannot do aal3" is false and
     * would mislead a host that HAS hardware-binding evidence; the true
     * statement is that NistAssuranceVocabulary caps at aal2 because
     * AssuranceFacts carries nothing an implementation could read to justify
     * more. Without the cap term the three names can simply co-occur; without
     * the cause, a reader cannot tell whether this is a bug or a design.
     */
    expect(docExplainsTogether([
        '/\baal3\b/',
        '/\baal2\b/',
        '/`?NistAssuranceVocabulary`?/',
        '/\b(caps?|capped|maximum|highest|ceiling|no higher|never above)\b/i',
        '/(`?AssuranceFacts`?|hardware[- ]?bind\w*|hardware[- ]?based)/i',
    ], readmeContents()))->toBeTrue();
});

it('says what a route configured for aal3 actually does', function (): void {
    /*
     * Naming the cap is not naming the consequence. A reader who learns the
     * vocabulary "caps at aal2" may still assume a higher requirement degrades,
     * throws, or is ignored. It does none of those, and all three properties
     * are load-bearing:
     *
     * - it REFUSES rather than degrading, so the refusal term is required and
     *   a bare "never" no longer satisfies it -- "aal3 is never emitted" is a
     *   fact about the vocabulary that says nothing about request handling;
     * - it does so SILENTLY, which is why nobody discovers this from a log;
     * - and PERMANENTLY, so waiting or re-authenticating never helps.
     *
     * The configuration term ties all of it to the route the host just wrote.
     */
    expect(docExplainsTogether([
        '/\baal3\b/',
        '/\b(route|requirement|middleware|map|configur\w+)\b/i',
        '/\b(unreachable|fails? closed|always refuses?)\b/i',
        '/\b(silent\w*|quietly|without (an )?error|no error|nothing in the log)\b/i',
        '/\b(forever|permanent\w*|never)\b/i',
        /*
         * Scope, in the same block. Unscoped, this rule blesses the false
         * universal -- "an aal3 route is permanently unreachable" -- which
         * contradicts the extension point the next rule requires. It is
         * unreachable UNDER THE SHIPPED VOCABULARY, and a reader who takes the
         * stronger reading will not go looking for the way out.
         */
        '/(`?NistAssuranceVocabulary`?|\bshipped\b|\bdefault\b)/i',
    ], readmeContents()))->toBeTrue();
});

it('names what a custom vocabulary would have to do', function (): void {
    /*
     * A host that DOES capture hardware binding -- WebAuthn backup-eligibility
     * and backup-state flags, or attestation -- can ship a vocabulary that
     * emits aal3. Documenting the cap without the extension point turns a
     * configuration limit into an apparent product limit. The verb is required:
     * mentioning the interface next to aal3 does not tell a reader that
     * implementing it is what lifts the ceiling.
     */
    expect(docExplainsTogether([
        '/\baal3\b/',
        '/`?AssuranceVocabulary`?/',
        '/\b(emit|derive|return|produce)\w*\b/i',
        '/\b(custom|own|your|implement)\w*\b/i',
    ], readmeContents()))->toBeTrue();
});

it('warns at the surface that accepts the level', function (): void {
    /*
     * Placement, not presence. The warning has to sit with the surface that
     * takes the value -- the ability map or the middleware alias -- because a
     * host copying that example is the one about to make the mistake.
     *
     * The ceiling term is required here too. Without it this rule is satisfied
     * by prose that is actively wrong: "`assurance_requirements` accepts aal0
     * through aal3" names both and teaches the opposite of the truth.
     */
    expect(docExplainsTogether([
        '/\baal3\b/',
        '/(assurance_requirements|vouch\.assurance)/',
        '/\b(caps?|capped|aal2|unreachable|never|fails? closed)\b/i',
    ], readmeContents()))->toBeTrue();
});

/**
 * The class bodies in a fence that implement AssuranceVocabulary, removed.
 *
 * Tokenised rather than pattern-matched, and the reason is a defect the regex
 * version actually had: it counted `{` and `}` inside string literals, so a
 * legitimate definition containing `return '}';` was rejected and a contrived
 * snippet could push the removal past the end of the class. PHP's own lexer
 * knows the difference between a brace and a character in a string, and there
 * is no reason to re-derive that badly.
 *
 * Scoped to the DEFINITION, not the fence: a fence can perfectly well show a
 * vocabulary class and, three lines below it, a live ability map naming aal3.
 * A fence-wide allowance hands the reader the broken half.
 *
 * Fails CLOSED, and the language tag is part of that. An earlier version
 * stripped the tag and prepended `<?php` before lexing, which handed the
 * allowance to any fence at all: a ```yaml block containing something shaped
 * like a class would tokenise as PHP and take the exemption with it. The
 * allowance now requires the fence to CLAIM to be PHP. A fence that does not,
 * or that cannot be tokenised into a bounded class body, is returned whole —
 * so anything it names is judged.
 */
function readmeWithoutVocabularyDefinitions(string $fence): string
{
    $live = readmeUncommented($fence);

    $language = '';
    if (preg_match('/^(?:```|~~~)([^\n]*)/', ltrim($live), $tag) === 1) {
        $language = strtolower(trim($tag[1]));
    }

    $body = (string) preg_replace('/^(?:```|~~~)[^\n]*\n|(?:```|~~~)\s*$/', '', $live);

    // An untagged fence counts only when it says `<?php` itself. Anything else
    // is judged whole rather than lexed as a language it never claimed to be.
    $isPhp = $language === 'php' || ($language === '' && str_contains($body, '<?php'));

    if (! $isPhp) {
        return $live;
    }

    if (! str_contains($body, '<?php')) {
        $body = "<?php\n" . $body;
    }

    $tokens = @token_get_all($body);

    // Accepted spellings of the contract: the bare name, plus every alias the
    // fence itself establishes. `preg_match_all` returns a COUNT -- an earlier
    // version compared it to 1 and so ignored a second alias entirely.
    $names = ['assurancevocabulary'];
    if (preg_match_all('/use\s+[\w\\\\]*AssuranceVocabulary\s+as\s+(\w+)\s*;/', $body, $aliases) > 0) {
        foreach ($aliases[1] as $alias) {
            $names[] = strtolower($alias);
        }
    }

    $text = static fn (array|string $token): string => is_array($token) ? $token[1] : $token;
    $isImplements = static fn (array|string $token): bool => is_array($token) && $token[0] === T_IMPLEMENTS;

    $drop = [];
    $count = count($tokens);

    for ($i = 0; $i < $count; $i++) {
        if (! $isImplements($tokens[$i])) {
            continue;
        }

        // Collect the implemented names up to the opening brace.
        $matched = false;
        $open = null;

        for ($j = $i + 1; $j < $count; $j++) {
            $piece = $text($tokens[$j]);

            if ($piece === '{') {
                $open = $j;
                break;
            }

            $segments = explode('\\', trim($piece));
            $last = strtolower(trim((string) end($segments)));

            if ($last !== '' && in_array($last, $names, true)) {
                $matched = true;
            }
        }

        if (! $matched || $open === null) {
            continue;
        }

        $depth = 0;

        for ($j = $open; $j < $count; $j++) {
            $piece = $text($tokens[$j]);

            if ($piece === '{') {
                $depth++;
            } elseif ($piece === '}') {
                $depth--;

                if ($depth === 0) {
                    foreach (range($open, $j) as $index) {
                        $drop[$index] = true;
                    }

                    $i = $j;
                    break;
                }
            }
        }

        // An unbounded class body means the snippet cannot be trusted to say
        // where the definition ends. Judge the whole fence rather than guess.
        if ($depth !== 0) {
            return $live;
        }
    }

    $kept = '';

    foreach ($tokens as $index => $token) {
        if (! isset($drop[$index])) {
            $kept .= $text($token);
        }
    }

    return $kept;
}

/**
 * Fences that put `aal3` somewhere a reader can copy it into service.
 *
 * An ALLOWLIST, scoped to the definition. An earlier version flagged a fence
 * only when `aal3` sat beside an accepting surface, which a two-fence
 * composition walks straight past: one fence sets a constant to 'aal3', the
 * next feeds it into the alias, and neither contains both halves while together
 * they configure a route nobody can reach.
 *
 * So `aal3` is permitted in exactly one place: inside a class implementing the
 * vocabulary contract. That is the extension point the prose rules require
 * explained, and showing it is the clearest way to explain it. Anywhere else --
 * including elsewhere in the very same fence -- the level is being consumed
 * rather than defined, and consuming it is what breaks.
 *
 * @param  list<string>  $fences
 * @return list<string>
 */
function fencesOfferingAal3(array $fences): array
{
    return array_values(array_filter(
        $fences,
        static fn (string $fence): bool => preg_match('/\baal3\b/', readmeWithoutVocabularyDefinitions($fence)) === 1,
    ));
}

/**
 * Copyable `aal3` OUTSIDE a fenced block: inline code spans and indented blocks.
 *
 * The fence rule scans fences, which is not the same as scanning what a reader
 * can copy. An inline span reading `'invoices.approve' => 'aal3'`, or a
 * four-space indented configuration line, is just as copyable and just as
 * broken, and would ship beside otherwise-correct prose.
 *
 * The test is narrower here than inside a fence, and it has to be: the prose
 * rules REQUIRE the document to name `aal3` in running text, almost always in
 * an inline span. So a bare mention is permitted, and what is flagged is a
 * mention sitting in something shaped like configuration — an accepting
 * surface, or the fat arrow of an ability map.
 *
 * @return list<string>
 */
function copyableAal3OutsideFences(string $markdown): array
{
    // Fences are the other rule's business; remove them so a config line inside
    // one is not reported twice under two different names.
    $outside = (string) preg_replace('/(```|~~~).*?\1/s', '', $markdown);

    $candidates = [];

    if (preg_match_all('/`[^`\n]*`/', $outside, $spans) > 0) {
        foreach ($spans[0] as $span) {
            $candidates[] = $span;
        }
    }

    /*
     * Contiguous indented lines are ONE block, not many. Split per line, an
     * indented `assurance_requirements:` followed by `invoices.approve: aal3`
     * passes every line individually while handing the reader a broken
     * configuration to copy whole.
     */
    $block = [];

    foreach (array_merge(explode("\n", $outside), ['']) as $line) {
        if (preg_match('/^(?: {4,}|\t)\S/', $line) === 1) {
            $block[] = $line;

            continue;
        }

        if ($block !== []) {
            $candidates[] = implode("\n", $block);
            $block = [];
        }
    }

    return array_values(array_filter($candidates, static function (string $snippet): bool {
        if (preg_match('/\baal3\b/', $snippet) !== 1) {
            return false;
        }

        return preg_match('/(assurance_requirements|vouch\.assurance|=>|->middleware\()/', $snippet) === 1;
    }));
}

it('does not offer aal3 anywhere a reader can copy it into service', function (): void {
    expect(fencesOfferingAal3(readmeFences()))->toBe([])
        ->and(copyableAal3OutsideFences(readmeContents()))->toBe([]);
});

it('permits aal3 named in running prose', function (): void {
    /*
     * Required, not merely tolerated: four of the five prose rules cannot be
     * satisfied without naming the level, and an inline span is how a document
     * names an identifier. A guard that flagged every inline `aal3` would put
     * this suite in contradiction with itself.
     */
    $prose = "A route requiring `aal3` is unreachable under the shipped vocabulary.";

    expect(copyableAal3OutsideFences($prose))->toBe([]);
});

it('catches an inline span that configures aal3', function (): void {
    $span = "Set `'invoices.approve' => 'aal3'` in the map.";

    expect(copyableAal3OutsideFences($span))->toBe(["`'invoices.approve' => 'aal3'`"]);
});

it('catches an indented configuration split across lines', function (): void {
    /*
     * The evasion a per-line rule leaves open. Neither line names both the
     * surface and the level; together they are a copyable broken map.
     */
    $indented = "Configure it:\n\n    assurance_requirements:\n      invoices.approve: aal3\n";

    expect(copyableAal3OutsideFences($indented))
        ->toBe(["    assurance_requirements:\n      invoices.approve: aal3"]);
});

it('catches an indented configuration block naming aal3', function (): void {
    /*
     * An indented block carries no language tag, so it cannot claim to be a
     * vocabulary definition. A definition example belongs in a tagged php
     * fence, where the allowance can be granted safely.
     */
    $indented = "Configure it:\n\n    'invoices.approve' => 'aal3',\n";

    expect(copyableAal3OutsideFences($indented))->toBe(["    'invoices.approve' => 'aal3',"]);
});

it('permits aal3 inside a vocabulary definition, which is the way out', function (): void {
    $definition = "```php\nfinal class HardwareBoundVocabulary implements AssuranceVocabulary\n{\n    public function name(AssuranceFacts \$facts): string\n    {\n        return \$facts->phishingResistant ? 'aal3' : 'aal2';\n    }\n}\n```";

    expect(fencesOfferingAal3([$definition]))->toBe([]);
});

it('permits a definition written with a fully qualified contract', function (): void {
    // A compact snippet may skip the import. Rejecting it would push the
    // documentation toward worse code to satisfy the guard.
    $definition = "```php\nfinal class V implements \\Fissible\\Vouch\\Kernel\\Assurance\\AssuranceVocabulary\n{\n    public function name(\$facts): string\n    {\n        return 'aal3';\n    }\n}\n```";

    expect(fencesOfferingAal3([$definition]))->toBe([]);
});

it('permits a definition written through an aliased import', function (): void {
    $definition = "```php\nuse Fissible\\Vouch\\Kernel\\Assurance\\AssuranceVocabulary as Vocabulary;\n\nfinal class V implements Vocabulary\n{\n    public function name(\$facts): string\n    {\n        return 'aal3';\n    }\n}\n```";

    expect(fencesOfferingAal3([$definition]))->toBe([]);
});

it('catches a live aal3 consumer sharing a fence with a definition', function (): void {
    /*
     * The evasion a fence-wide allowance leaves open: the definition is
     * legitimate, and the ability map three lines below it is the broken half a
     * reader copies.
     */
    $mixed = "```php\nfinal class V implements AssuranceVocabulary\n{\n    public function name(\$facts): string\n    {\n        return 'aal3';\n    }\n}\n\n// config/vouch.php\n'assurance_requirements' => ['invoices.approve' => 'aal3'],\n```";

    expect(fencesOfferingAal3([$mixed]))->toBe([$mixed]);
});

it('permits a definition whose body contains a brace in a string', function (): void {
    /*
     * The defect that retired the regex matcher: it counted braces inside
     * string literals, so this legitimate class looked unbalanced and the
     * allowance was withheld from the one example that explains the way out.
     */
    $definition = "```php\nfinal class V implements AssuranceVocabulary\n{\n    public function name(\$facts): string\n    {\n        \$brace = '}';\n\n        return \$brace === '}' ? 'aal3' : 'aal2';\n    }\n}\n```";

    expect(fencesOfferingAal3([$definition]))->toBe([]);
});

it('permits a definition when the fence establishes several aliases', function (): void {
    // The count comparison was `=== 1`, so a second alias was ignored entirely
    // and a definition written through it was judged as a consumer.
    $definition = "```php\nuse Fissible\\Vouch\\Kernel\\Assurance\\AssuranceVocabulary as Vocabulary;\nuse Fissible\\Vouch\\Kernel\\Assurance\\AssuranceVocabulary as Contract;\n\nfinal class V implements Contract\n{\n    public function name(\$facts): string\n    {\n        return 'aal3';\n    }\n}\n```";

    expect(fencesOfferingAal3([$definition]))->toBe([]);
});

it('judges a non-php fence that merely looks like a definition', function (): void {
    /*
     * The allowance is for PHP, and the fence has to say so. Stripping the
     * language tag and lexing everything as PHP handed the exemption to any
     * block whose text happened to parse -- which is the opposite of failing
     * closed, and was true of this guard until it was measured.
     */
    $yaml = "```yaml\n# a config sketch, not a class\nvocabulary: V implements AssuranceVocabulary { name: 'aal3' }\nassurance_requirements:\n  invoices.approve: aal3\n```";

    expect(fencesOfferingAal3([$yaml]))->toBe([$yaml]);
});

it('judges a fence whose class body never closes', function (): void {
    /*
     * Fails closed. An unbounded body means the snippet cannot say where the
     * definition ends, so the allowance is refused rather than guessed at --
     * otherwise a truncated example becomes a way to smuggle a live level past
     * the guard.
     */
    $truncated = "```php\nfinal class V implements AssuranceVocabulary\n{\n    public function name(\$facts): string\n    {\n        return 'aal3';\n```";

    expect(fencesOfferingAal3([$truncated]))->toBe([$truncated]);
});

it('catches an aal3 configuration split across two fences', function (): void {
    $sets = "```php\nconst APPROVAL_ASSURANCE = 'aal3';\n```";
    $uses = "```php\nRoute::post('/approve', ...)->middleware('vouch.assurance:' . APPROVAL_ASSURANCE);\n```";

    expect(fencesOfferingAal3([$sets, $uses]))->toBe([$sets]);
});

it('does not count a commented aal3 line as copyable', function (): void {
    $teaching = "```php\n// 'invoices.approve' => 'aal3', // unreachable: the shipped vocabulary caps at aal2\n'invoices.approve' => 'aal2',\n```";

    expect(fencesOfferingAal3([$teaching]))->toBe([]);
});

it('explains the morph map hazard as one coherent warning', function (): void {
    /*
     * Deliberately one block rather than four assertions that three vague
     * paragraphs in two different documents could satisfy between them. The
     * hazard is only actionable as a whole: the map supplies the provider half
     * of every persisted subject key, so records written before a change stop
     * binding, Vouch will not migrate them, and the remedy is therefore to plan
     * the change rather than discover it.
     *
     * Any one of those alone misleads. "Sessions break" without "no migration"
     * suggests waiting for a fix; "does not migrate" without the consequence
     * reads as a limitation of something optional.
     *
     * Two sentences carry all of it, so this constrains coherence rather than
     * wording.
     */
    expect(hostDocsExplainTogether([
        '/morph ?[mM]ap/',
        /*
         * The trigger, bound to the map itself rather than merely present in
         * the same block. Without it a block can describe the hazard without
         * saying that CHANGING the map causes it, leaving a reader unsure
         * whether merely having one is dangerous; without the ADJACENCY an
         * unrelated "add" or "register" elsewhere in the paragraph satisfies
         * it and proves no causality at all.
         */
        '/((chang|renam|remov|register|add)\w*[^.]{0,40}morph ?map|morph ?map[^.]{0,40}(chang|renam|remov|register|add)\w*)/i',
        '/(`?SubjectKey`?|provider|session|token)/i',
        '/\b(stored|persisted|written|existing)\b/i',
        '/\b(re-?authenticat\w*|stops? binding|no longer bind\w*|invalidat\w*)\b/i',
        '/\b(does not migrate|never migrates?|no migration|not migrated)\b/i',
        '/\b(plan|rotation|rotate|schedule)\w*\b/i',
    ]))->toBeTrue();
});
