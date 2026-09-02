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

it('ships a shipped vocabulary that declares its own range', function (): void {
    /*
     * The out-of-the-box case, and the reason this issue is worth doing at all:
     * a host that configures aal3 against the default vocabulary is told so
     * without opting into anything.
     */
    expect(new NistAssuranceVocabulary())->toBeInstanceOf(ReportsReachableLevels::class)
        ->and((new NistAssuranceVocabulary())->reachableLevels())->toBe(['aal0', 'aal1', 'aal2']);
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
     * holds positive evidence, so the command may say so -- this is the one
     * direction a probe is allowed to speak in.
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

it('reports undetermined rather than unreachable when nothing can settle it', function (): void {
    /*
     * THE test. An undeclared vocabulary whose aal3 branch the grid does not
     * reach. The command knows nothing, and saying "unreachable" here would be
     * a false report against a configuration that may well work -- the probe's
     * grid is a guess about how a host writes its rules, not a proof.
     */
    app()->instance(AssuranceVocabulary::class, new class implements AssuranceVocabulary
    {
        public function name(AssuranceFacts $facts): string
        {
            // Reachable, but only far outside any bounded grid.
            return $facts->distinctCredentialCount >= 97 ? 'aal3' : 'aal1';
        }
    });

    expect(derivabilityOf(assuranceMapReport(), 'invoices.approve'))->toBe('undetermined');
});

it('warns and still exits zero by default', function (): void {
    app()->instance(AssuranceVocabulary::class, declaringVocabulary(['aal0', 'aal1', 'aal2']));

    expect(Artisan::call('vouch:assurance-map'))->toBe(0)
        ->and(Artisan::output())->toContain('aal3');
});

it('fails under strict when the vocabulary declares the level unreachable', function (): void {
    app()->instance(AssuranceVocabulary::class, declaringVocabulary(['aal0', 'aal1', 'aal2']));

    expect(Artisan::call('vouch:assurance-map', ['--strict' => true]))->toBe(1);
});

it('fails under strict when nothing could settle the question', function (): void {
    /*
     * Strict means prove it. An undetermined answer is the ABSENCE of proof,
     * not evidence of safety, and treating it as a pass would let the gate
     * report success on precisely the configurations it cannot vouch for. The
     * remedy available to the host is to declare.
     */
    app()->instance(AssuranceVocabulary::class, new class implements AssuranceVocabulary
    {
        public function name(AssuranceFacts $facts): string
        {
            return $facts->distinctCredentialCount >= 97 ? 'aal3' : 'aal1';
        }
    });

    expect(Artisan::call('vouch:assurance-map', ['--strict' => true]))->toBe(1);
});

it('does not fail under strict on probe evidence alone', function (): void {
    /*
     * Observed is positive evidence. Failing here would punish a host whose
     * configuration the command just watched work.
     *
     * This passes BEFORE the feature exists, because a command with no
     * derivability logic fails nothing -- it is a non-regression guard rather
     * than RED evidence, and its value is that it fails if the implementation
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
     * A vocabulary cannot usefully declare a level no requirement can name:
     * AssuranceRequirement only accepts the canonical ladder. Accepting it
     * silently would let a typo -- 'aal2 ' or 'AAL2' -- read as a range that
     * covers nothing.
     */
    app()->instance(AssuranceVocabulary::class, declaringVocabulary(['aal0', 'aal1', 'high']));

    $report = assuranceMapReport();

    expect(json_encode($report['vocabulary'] ?? null))->toContain('high')
        ->and(Artisan::call('vouch:assurance-map', ['--strict' => true]))->toBe(1);
});

it('reports a probe that contradicts a declaration', function (): void {
    /*
     * The one case where the probe outranks the declaration, because it holds a
     * counter-example: the vocabulary emitted a level it says it cannot. That
     * is a defect in host code, and silently taking either side hides it.
     */
    app()->instance(AssuranceVocabulary::class, declaringVocabulary(
        ['aal0', 'aal1'],
        static fn (AssuranceFacts $facts): string => $facts->distinctCredentialCount >= 2 ? 'aal2' : 'aal1',
    ));

    $report = assuranceMapReport();

    expect(json_encode($report['vocabulary'] ?? null))->toContain('aal2')
        ->and(Artisan::call('vouch:assurance-map', ['--strict' => true]))->toBe(1);
});

it('does not treat incomplete probe coverage as a fault', function (): void {
    /*
     * The opposite direction, and NOT symmetrical with the one above. A
     * declared level the grid never reached says something about the grid, not
     * about the vocabulary -- the declaration is authoritative and stands.
     */
    app()->instance(AssuranceVocabulary::class, declaringVocabulary(
        ['aal0', 'aal1', 'aal2', 'aal3'],
        static fn (AssuranceFacts $facts): string => $facts->distinctCredentialCount >= 97 ? 'aal3' : 'aal1',
    ));

    expect(derivabilityOf(assuranceMapReport(), 'invoices.approve'))->toBe('declared')
        ->and(Artisan::call('vouch:assurance-map', ['--strict' => true]))->toBe(0);
});

it('probes a bounded number of times', function (): void {
    /*
     * The probe calls HOST code. An unbounded grid would be a denial of service
     * a host inflicts on itself by running a diagnostic, and the bound is what
     * makes the advisory verdict affordable enough to run by default.
     *
     * The cap is deliberately loose: what matters is that a bound EXISTS, not
     * its exact value, which is an implementation choice this should not pin.
     */
    $vocabulary = new ProbeCountingVocabulary();
    app()->instance(AssuranceVocabulary::class, $vocabulary);

    assuranceMapReport();

    expect($vocabulary->calls)->toBeGreaterThan(0)
        ->and($vocabulary->calls)->toBeLessThan(2000);
});
