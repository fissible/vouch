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
 * Fences that put `aal3` somewhere a reader can copy it into service.
 *
 * The rule is an ALLOWLIST, and that is the point. An earlier version flagged a
 * fence only when `aal3` sat beside an accepting surface -- `assurance_requirements`,
 * `vouch.assurance`, `->middleware(` -- which a two-fence composition walks
 * straight past: one fence sets a host constant to 'aal3', the next feeds that
 * constant into the alias, and neither fence contains both halves while together
 * they configure a route nobody can reach.
 *
 * So `aal3` is permitted in exactly one shape: a fence DEFINING a vocabulary.
 * That is the extension point the prose rules require explained, and showing it
 * is the clearest way to explain it. Everywhere else the level is being
 * consumed rather than defined, and consuming it is what breaks.
 *
 * Comments are stripped first, on the reasoning ReadmePositioningTest gives for
 * routes: a commented line inside a fence is prose in a code font, it cannot be
 * pasted into service, and showing the mistake beside its correction is a
 * legitimate way to teach this particular footgun.
 *
 * @param  list<string>  $fences
 * @return list<string>
 */
function fencesOfferingAal3(array $fences): array
{
    return array_values(array_filter($fences, static function (string $fence): bool {
        $live = readmeUncommented($fence);

        if (preg_match('/\baal3\b/', $live) !== 1) {
            return false;
        }

        $definesVocabulary = preg_match('/implements\s+AssuranceVocabulary\b/', $live) === 1
            || preg_match('/function\s+name\s*\(\s*AssuranceFacts/', $live) === 1;

        return ! $definesVocabulary;
    }));
}

it('does not offer aal3 anywhere a reader can copy it into service', function (): void {
    expect(fencesOfferingAal3(readmeFences()))->toBe([]);
});

it('permits aal3 in a vocabulary definition, which is the way out', function (): void {
    // The rule must not forbid the example that makes the ceiling survivable.
    $definition = <<<'FENCE'
    ```php
    final class HardwareBoundVocabulary implements AssuranceVocabulary
    {
        public function name(AssuranceFacts $facts): string
        {
            return $facts->phishingResistant ? 'aal3' : 'aal2';
        }
    }
    ```
    FENCE;

    expect(fencesOfferingAal3([$definition]))->toBe([]);
});

it('catches an aal3 configuration split across two fences', function (): void {
    /*
     * The hole an accepting-surface rule leaves open. Neither fence names both
     * the level and the surface, and together they configure a dead route.
     */
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
