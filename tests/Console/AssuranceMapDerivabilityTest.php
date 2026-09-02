<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Kernel\Assurance\NistAssuranceVocabulary;
use Fissible\Vouch\Kernel\Assurance\ReportsReachableLevels;
use Fissible\Vouch\Tests\Support\Assurance\DeclaringVocabulary;
use Fissible\Vouch\Tests\Support\Assurance\ProbeCountingVocabulary;
use Illuminate\Support\Facades\Artisan;

/*
 * Issue #8 -- an assurance requirement no vocabulary can satisfy.
 *
 * §3f documented the aal2 ceiling; documentation relies on someone reading it,
 * and the failure it describes is silent. This makes the command say it.
 *
 * Scope: this file covers the DIAGNOSTIC only. That an underivable requirement
 * still fails closed at the route -- and that a host vocabulary which derives
 * the level satisfies it -- is proven in
 * tests/Authorization/UnreachableAal3RouteTest.php, and is not re-asserted
 * here. §3g's rule that runtime authorization is untouched by this feature
 * rests on that file, not on this one.
 *
 * The whole design is that the two sources of truth carry DIFFERENT authority.
 * A declaration is the vocabulary stating its own range and nothing can know
 * better. A probe constructs a bounded grid of facts and reports what it saw --
 * a lower bound, never a ceiling. So the tests below care less about the happy
 * path than about which verdict each source is allowed to produce, because a
 * false "unreachable" tells an operator to change a configuration that works.
 */

/** @return array<string, mixed> */
function assuranceMapReport(): array
{
    Artisan::call('vouch:assurance-map', ['--json' => true]);

    return jsonBody(Artisan::output());
}

/**
 * The derivability verdict for one ability, or fail loudly.
 *
 * @param  array<string, mixed>  $report
 */
function derivabilityOf(array $report, string $ability): string
{
    $rows = $report['requirements'] ?? null;

    if (! is_array($rows)) {
        throw new RuntimeException('vouch:assurance-map reported no requirements.');
    }

    foreach ($rows as $row) {
        if (is_array($row) && ($row['ability'] ?? null) === $ability) {
            return stringValue($row['derivable'] ?? null);
        }
    }

    throw new RuntimeException("vouch:assurance-map did not report on {$ability}.");
}

/** @param list<string> $levels */
function declaringVocabulary(array $levels, ?callable $rule = null): DeclaringVocabulary
{
    return new DeclaringVocabulary(
        $levels,
        $rule ?? static fn (AssuranceFacts $facts): string => $facts->distinctCredentialCount >= 2 ? 'aal2' : 'aal1',
    );
}

beforeEach(function (): void {
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal3']]);

    /*
     * Declared deliberately. --strict ALREADY fails on an ability that was
     * never opted into, so without this every strict assertion below would
     * pass on the pre-existing check and prove nothing about derivability --
     * one of them did, before this line existed.
     */
    config(['vouch.declared_abilities' => ['invoices.approve']]);
});

/**
 * The vocabulary section of the report, or fail loudly.
 *
 * @param  array<string, mixed>  $report
 * @return array<string, mixed>
 */
function vocabularyReport(array $report): array
{
    $section = $report['vocabulary'] ?? null;

    if (! is_array($section)) {
        throw new RuntimeException('vouch:assurance-map reported no vocabulary section.');
    }

    /** @var array<string, mixed> $section */
    return $section;
}

/** A vocabulary with no declaration that never emits the level under test. */
function silentVocabulary(): AssuranceVocabulary
{
    /*
     * Never emits aal3 under ANY facts, which is what makes it usable for
     * classification. An earlier draft used a vocabulary whose aal3 branch
     * needed 97 credentials, quietly assuming the grid stayed smaller than
     * that -- a legitimate implementation probing further would have turned
     * the verdict into `observed` and the test green for the wrong reason.
     */
    return new class implements AssuranceVocabulary
    {
        public function name(AssuranceFacts $facts): string
        {
            return $facts->distinctCredentialCount >= 2 ? 'aal2' : 'aal1';
        }
    };
}

it('reports the shipped vocabulary as unable to derive aal3, through the command', function (): void {
    /*
     * The out-of-the-box case, driven through the COMMAND against the default
     * container binding. Asserting that NistAssuranceVocabulary implements the
     * capability proves only that the class does; the command could ignore the
     * capability entirely and that assertion would still pass.
     */
    expect(derivabilityOf(assuranceMapReport(), 'invoices.approve'))->toBe('undeclared');
});

it('classifies every level on the ladder, not only the one that motivated this', function (): void {
    /*
     * An implementation hard-coded around aal3 satisfies every other test in
     * this file. Four requirements at once, across the whole canonical ladder,
     * against a declaration covering three of them.
     */
    config(['vouch.assurance_requirements' => [
        'a.zero' => 'aal0',
        'a.one' => 'aal1',
        'a.two' => 'aal2',
        'a.three' => 'aal3',
    ]]);
    config(['vouch.declared_abilities' => ['a.zero', 'a.one', 'a.two', 'a.three']]);
    app()->instance(AssuranceVocabulary::class, declaringVocabulary(['aal0', 'aal1', 'aal2']));

    $report = assuranceMapReport();

    expect(derivabilityOf($report, 'a.zero'))->toBe('declared')
        ->and(derivabilityOf($report, 'a.one'))->toBe('declared')
        ->and(derivabilityOf($report, 'a.two'))->toBe('declared')
        ->and(derivabilityOf($report, 'a.three'))->toBe('undeclared');
});

it('reports an authoritative absence when the vocabulary declares its range', function (): void {
    app()->instance(AssuranceVocabulary::class, declaringVocabulary(['aal0', 'aal1', 'aal2']));

    expect(derivabilityOf(assuranceMapReport(), 'invoices.approve'))->toBe('undeclared');
});

it('reports declared when the level is in the range', function (): void {
    app()->instance(AssuranceVocabulary::class, declaringVocabulary(
        ['aal0', 'aal1', 'aal2', 'aal3'],
        static fn (AssuranceFacts $facts): string => $facts->distinctCredentialCount >= 2 ? 'aal3' : 'aal1',
    ));

    expect(derivabilityOf(assuranceMapReport(), 'invoices.approve'))->toBe('declared');
});

it('reports observed, not declared, when only the probe saw the level', function (): void {
    /*
     * A vocabulary with no declaration that plainly does emit aal3. The probe
     * holds positive evidence, so the command may say so -- the one direction
     * a probe is allowed to speak in.
     */
    app()->instance(AssuranceVocabulary::class, new class implements AssuranceVocabulary
    {
        public function name(AssuranceFacts $facts): string
        {
            return $facts->distinctCredentialCount >= 2 ? 'aal3' : 'aal1';
        }
    });

    expect(derivabilityOf(assuranceMapReport(), 'invoices.approve'))->toBe('observed');
});

it('observes a level that depends on a fact other than the credential count', function (): void {
    /*
     * Every other positive fixture in this file branches on
     * distinctCredentialCount, so a degenerate "probe" that constructed ONE
     * facts value with two credentials would satisfy the observed,
     * contradiction, call-count and budget tests alike while never exercising
     * the closed shape §3g relies on.
     *
     * This one keys on phishing resistance instead. A probe that does not vary
     * that dimension reports undetermined and fails here.
     */
    app()->instance(AssuranceVocabulary::class, new class implements AssuranceVocabulary
    {
        public function name(AssuranceFacts $facts): string
        {
            return $facts->allPhishingResistant && $facts->distinctCredentialCount > 0
                ? 'aal3'
                : 'aal1';
        }
    });

    expect(derivabilityOf(assuranceMapReport(), 'invoices.approve'))->toBe('observed');
});

it('observes a level that depends on a multi-factor credential', function (): void {
    // A second dimension, for the same reason: two independent fields have to
    // move before a grid can be called one.
    app()->instance(AssuranceVocabulary::class, new class implements AssuranceVocabulary
    {
        public function name(AssuranceFacts $facts): string
        {
            return $facts->hasMultiFactorCredential ? 'aal3' : 'aal1';
        }
    });

    expect(derivabilityOf(assuranceMapReport(), 'invoices.approve'))->toBe('observed');
});

it('reports undetermined rather than unreachable when nothing can settle it', function (): void {
    /*
     * THE test. No declaration, and a vocabulary the probe can watch as long as
     * it likes without ever seeing aal3. The command knows nothing, and saying
     * "unreachable" would be a false report -- the vocabulary might branch on
     * facts no grid constructs, and the command cannot tell that apart from
     * this.
     */
    app()->instance(AssuranceVocabulary::class, silentVocabulary());

    expect(derivabilityOf(assuranceMapReport(), 'invoices.approve'))->toBe('undetermined');
});

it('names the verdict in the default rendering, not merely the level', function (): void {
    /*
     * An earlier version asserted the output contained "aal3", which the table
     * already prints as the configured level -- it passed with no derivability
     * logic at all. The rendering has to carry the FINDING.
     */
    app()->instance(AssuranceVocabulary::class, declaringVocabulary(['aal0', 'aal1', 'aal2']));

    expect(Artisan::call('vouch:assurance-map'))->toBe(0);

    $output = Artisan::output();

    expect($output)->toContain('invoices.approve')
        ->and($output)->toContain('undeclared');
});

it('fails under strict when the vocabulary declares the level unreachable', function (): void {
    app()->instance(AssuranceVocabulary::class, declaringVocabulary(['aal0', 'aal1', 'aal2']));

    expect(Artisan::call('vouch:assurance-map', ['--strict' => true]))->toBe(1);
});

it('fails under strict when nothing could settle the question', function (): void {
    /*
     * Strict means prove it. An undetermined answer is the ABSENCE of proof,
     * not evidence of safety, and treating it as a pass would report success on
     * precisely the configurations the command cannot vouch for. The remedy
     * available to the host is to declare.
     */
    app()->instance(AssuranceVocabulary::class, silentVocabulary());

    expect(Artisan::call('vouch:assurance-map', ['--strict' => true]))->toBe(1);
});

it('does not fail under strict on probe evidence alone', function (): void {
    /*
     * Observed is positive evidence. Failing here would punish a host whose
     * configuration the command just watched work.
     *
     * This passes BEFORE the feature exists, because a command with no
     * derivability logic fails nothing -- a non-regression guard rather than
     * RED evidence, and its value is that it fails if the implementation
     * reaches for strictness it was not asked for.
     */
    app()->instance(AssuranceVocabulary::class, new class implements AssuranceVocabulary
    {
        public function name(AssuranceFacts $facts): string
        {
            return $facts->distinctCredentialCount >= 2 ? 'aal3' : 'aal1';
        }
    });

    expect(Artisan::call('vouch:assurance-map', ['--strict' => true]))->toBe(0);
});

it('refuses a declaration naming a level outside the ladder', function (): void {
    /*
     * The requirement here is aal1, which the declaration DOES contain, so the
     * only thing strict can be failing on is the invalid entry. An earlier
     * version required aal3 and proved nothing: strict failed because aal3 was
     * undeclared, while `high` was merely echoed into the output.
     */
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal1']]);
    app()->instance(AssuranceVocabulary::class, declaringVocabulary(['aal0', 'aal1', 'high']));

    $report = assuranceMapReport();

    expect(derivabilityOf($report, 'invoices.approve'))->toBe('declared')
        ->and(json_encode(vocabularyReport($report)['errors'] ?? null))->toContain('high')
        ->and(Artisan::call('vouch:assurance-map', ['--strict' => true]))->toBe(1);
});

it('reports a probe that contradicts a declaration', function (): void {
    /*
     * The one case where the probe outranks the declaration, because it holds a
     * counter-example: the vocabulary emitted a level it says it cannot.
     *
     * Same isolation as above -- the requirement is aal1 and IS declared, so
     * strict cannot be failing for any other reason.
     */
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal1']]);
    app()->instance(AssuranceVocabulary::class, declaringVocabulary(
        ['aal0', 'aal1'],
        static fn (AssuranceFacts $facts): string => $facts->distinctCredentialCount >= 2 ? 'aal2' : 'aal1',
    ));

    $report = assuranceMapReport();

    expect(derivabilityOf($report, 'invoices.approve'))->toBe('declared')
        ->and(json_encode(vocabularyReport($report)['errors'] ?? null))->toContain('aal2')
        ->and(Artisan::call('vouch:assurance-map', ['--strict' => true]))->toBe(1);
});

it('still probes when a declaration exists, and reports incomplete coverage', function (): void {
    /*
     * Not symmetrical with the contradiction above. A declared level the grid
     * never reached says something about the GRID, not the vocabulary, so the
     * declaration stands and strict passes.
     *
     * But the probe must still RUN: an implementation that skipped probing
     * whenever a declaration exists would return `declared` and satisfy every
     * other assertion here while never being able to find the contradiction the
     * previous test depends on. The call count is what proves it ran.
     */
    $vocabulary = declaringVocabulary(
        ['aal0', 'aal1', 'aal2', 'aal3'],
        static fn (AssuranceFacts $facts): string => $facts->distinctCredentialCount >= 97 ? 'aal3' : 'aal1',
    );
    app()->instance(AssuranceVocabulary::class, $vocabulary);

    $report = assuranceMapReport();

    expect(derivabilityOf($report, 'invoices.approve'))->toBe('declared')
        ->and($vocabulary->calls)->toBeGreaterThan(0)
        ->and(vocabularyReport($report)['unobserved_declared'] ?? null)->toBe(['aal3'])
        ->and(Artisan::call('vouch:assurance-map', ['--strict' => true]))->toBe(0);
});

it('does not list a declared level the probe did observe as unobserved', function (): void {
    /*
     * The exclusion half. The previous test only asks that the unreached level
     * APPEARS, which a report listing every declared level regardless would
     * also satisfy -- and that report would tell an operator their grid missed
     * things it plainly saw.
     *
     * aal1 and aal2 are both emitted by the rule below; only aal3 is out of
     * reach.
     */
    $vocabulary = declaringVocabulary(
        ['aal0', 'aal1', 'aal2', 'aal3'],
        static fn (AssuranceFacts $facts): string => $facts->distinctCredentialCount >= 2 ? 'aal2' : 'aal1',
    );
    app()->instance(AssuranceVocabulary::class, $vocabulary);

    $unobserved = vocabularyReport(assuranceMapReport())['unobserved_declared'] ?? null;

    expect($unobserved)->toBeArray()
        ->and($unobserved)->not->toContain('aal1')
        ->and($unobserved)->not->toContain('aal2')
        ->and($unobserved)->toContain('aal3');
});

it('probes within a stated budget', function (): void {
    /*
     * The probe calls HOST code, so its cost is a budget rather than an
     * implementation detail: a diagnostic that ran an unknown implementation an
     * unbounded number of times would be a denial of service a host inflicts on
     * itself by running it.
     *
     * This pins 2000 calls as that budget, inclusive. It cannot prove a UNIFORM bound --
     * it measures one execution -- and it is not trying to. It is the accepted
     * operational ceiling, and an implementation that exceeds it here has
     * chosen a grid that needs justifying.
     */
    $vocabulary = new ProbeCountingVocabulary();
    app()->instance(AssuranceVocabulary::class, $vocabulary);

    assuranceMapReport();

    expect($vocabulary->calls)->toBeGreaterThan(0)
        ->and($vocabulary->calls)->toBeLessThanOrEqual(2000);
});
