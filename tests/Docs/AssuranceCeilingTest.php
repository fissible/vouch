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
 * Brace-matched rather than regex-bounded, because the allowance has to be
 * scoped to the DEFINITION and not to the whole fence: a fence can perfectly
 * well show a vocabulary class and, three lines below it, a live ability map
 * naming aal3. A fence-wide test permits that mixed fence and hands the reader
 * the broken half.
 *
 * Alias-aware for the same reason the rule exists at all. A README may import
 * the contract under a shorter name, or spell it fully qualified inline, and a
 * guard that only recognises the bare class name would reject legitimate
 * examples and so push the documentation toward worse code.
 */
function readmeWithoutVocabularyDefinitions(string $fence): string
{
    $live = readmeUncommented($fence);

    // `use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary as Vocabulary;`
    $names = ['AssuranceVocabulary'];
    if (preg_match_all('/use\s+[\w\\\\]*AssuranceVocabulary\s+as\s+(\w+)\s*;/', $live, $aliases) === 1) {
        foreach ($aliases[1] as $alias) {
            $names[] = $alias;
        }
    }
    $alternation = implode('|', array_map(static fn (string $n): string => preg_quote($n, '/'), $names));

    // Optional namespace, so a fully qualified implements clause still counts.
    $pattern = '/implements\s+[^{]*(?:\\\\)?(?:' . $alternation . ')\b[^{]*\{/';

    while (preg_match($pattern, $live, $match, PREG_OFFSET_CAPTURE) === 1) {
        $open = (int) $match[0][1] + strlen($match[0][0]) - 1;
        $depth = 0;
        $close = null;

        for ($i = $open, $len = strlen($live); $i < $len; $i++) {
            if ($live[$i] === '{') {
                $depth++;
            } elseif ($live[$i] === '}') {
                $depth--;
                if ($depth === 0) {
                    $close = $i;
                    break;
                }
            }
        }

        // An unbalanced snippet is not a definition we can bound, so refuse to
        // grant it the allowance rather than silently swallowing the remainder.
        if ($close === null) {
            return $live;
        }

        $live = substr($live, 0, (int) $match[0][1]) . substr($live, $close + 1);
    }

    return $live;
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

it('does not offer aal3 anywhere a reader can copy it into service', function (): void {
    expect(fencesOfferingAal3(readmeFences()))->toBe([]);
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
