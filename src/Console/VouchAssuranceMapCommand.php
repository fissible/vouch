<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

use Fissible\Vouch\Authorization\AssuranceRequirements;
use Fissible\Vouch\Assurance\AssuranceLevelComparator;
use Fissible\Vouch\Http\Middleware\RequireAbilityAssurance;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Kernel\Assurance\ReportsReachableLevels;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use DateTimeImmutable;
use Illuminate\Console\Command;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Gate;
use JsonException;
use ReflectionMethod;
use RuntimeException;

/** Makes bounded strict-mode coverage and the survey's Gate seam visible to hosts. */
final class VouchAssuranceMapCommand extends Command
{
    protected $signature = 'vouch:assurance-map {--json : Emit machine-readable JSON} {--strict : Fail when a mapped ability is unknown}';
    protected $description = 'Report Vouch ability-to-assurance requirements and their known sources.';

    /** @throws JsonException */
    public function handle(AssuranceRequirements $requirements, Router $router, AssuranceVocabulary $vocabulary): int
    {
        $declared = AssuranceRequirements::declaredFrom(config('vouch.declared_abilities'));
        $gate = Gate::abilities();
        $vocabularyReport = $this->vocabularyReport($vocabulary);
        $rows = [];
        $unknown = [];
        $notProven = [];
        foreach ($requirements->all() as $ability => $level) {
            $source = array_key_exists($ability, $gate) ? 'gate' : (in_array($ability, $declared, true) ? 'declared' : 'unknown');
            $derivable = $this->derivability($level, $vocabularyReport['declared'], $vocabularyReport['observed']);
            $rows[] = compact('ability', 'level', 'source', 'derivable');
            if ($source === 'unknown') {
                $unknown[] = $ability;
            }
            if ($derivable === 'undeclared' || $derivable === 'undetermined') {
                $notProven[] = $ability;
            }
        }
        $groups = [];
        foreach ($router->getMiddlewareGroups() as $group => $middleware) {
            if (in_array(RequireAbilityAssurance::class, $middleware, true)) {
                $groups[] = $group;
            }
        }
        $report = [
            'requirements' => $rows,
            'unknown' => count($unknown),
            'enforced_groups' => $groups,
            'user_model_routes_to_gate' => $this->userModelRoutesToGate(),
            'vocabulary' => $vocabularyReport,
        ];
        if ($this->option('json') === true) {
            $this->line(json_encode($report, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        } else {
            $this->table(
                ['Ability', 'Level', 'Source', 'Derivable'],
                array_map(static fn (array $row): array => [$row['ability'], $row['level'], $row['source'], $row['derivable']], $rows),
            );
            $this->components->info('Unknown abilities: ' . ($unknown === [] ? 'none' : implode(', ', $unknown)) . '.');
            if ($notProven !== []) {
                $this->components->warn('Requirements not proven derivable: ' . implode(', ', $notProven) . '.');
            }
            foreach ($vocabularyReport['errors'] as $error) {
                $this->components->error($error);
            }
            if ($vocabularyReport['unobserved_declared'] !== []) {
                $this->components->warn('Declared vocabulary levels not observed by probe: ' . implode(', ', $vocabularyReport['unobserved_declared']) . '.');
            }
            $this->components->info('Enforced groups: ' . ($groups === [] ? 'none' : implode(', ', $groups)) . '.');
            if ($report['user_model_routes_to_gate'] === false) {
                $this->components->warn('Configured user model can() does not verifiably route to Gate.');
            } elseif ($report['user_model_routes_to_gate'] === null) {
                $this->components->error('Configured user model does not exist or is not configured.');
            }
        }

        if ($this->option('strict') === true) {
            try {
                // Gate registrations can be conditional or runtime-defined,
                // so they are useful report evidence but cannot bound strict
                // coverage. Only the explicit declared list is stable enough
                // to prove every configured requirement was opted into.
                $requirements->assertDeclared($declared);
            } catch (RuntimeException) {
                return CommandExit::Failure->value;
            }
            if ($notProven !== [] || $vocabularyReport['errors'] !== []) {
                return CommandExit::Failure->value;
            }
        }

        return CommandExit::Success->value;
    }

    private function userModelRoutesToGate(): ?bool
    {
        $model = config('auth.providers.users.model');
        if (! is_string($model) || ! class_exists($model)) {
            return null;
        }
        try {
            $userCan = new ReflectionMethod($model, 'can');
            $laravelCan = new ReflectionMethod(\Illuminate\Foundation\Auth\Access\Authorizable::class, 'can');
        } catch (\ReflectionException) {
            return false;
        }

        // Trait membership is not enough: a model can import Laravel's trait
        // and still override can(). Compare the method body origin so every
        // alternate implementation, package-provided or hand-rolled, warns.
        return $userCan->getFileName() === $laravelCan->getFileName()
            && $userCan->getStartLine() === $laravelCan->getStartLine();
    }

    /**
     * @return array{class: string, declared: list<string>|null, observed: list<string>, errors: list<string>, unobserved_declared: list<string>}
     */
    private function vocabularyReport(AssuranceVocabulary $vocabulary): array
    {
        $declared = $vocabulary instanceof ReportsReachableLevels ? $vocabulary->reachableLevels() : null;
        $observed = $this->observedLevels($vocabulary);
        $errors = [];

        if ($declared !== null) {
            foreach ($declared as $level) {
                if (! AssuranceLevelComparator::isKnown($level)) {
                    $errors[] = "Vocabulary declared non-canonical assurance level {$level}.";
                }
            }
            foreach ($observed as $level) {
                if (! in_array($level, $declared, true)) {
                    $errors[] = "Vocabulary probe observed {$level}, which the vocabulary did not declare.";
                }
            }
        }

        $unobservedDeclared = $declared === null
            ? []
            : array_values(array_filter(
                AssuranceLevelComparator::ORDER,
                static fn (string $level): bool => in_array($level, $declared, true) && ! in_array($level, $observed, true),
            ));

        return [
            'class' => $vocabulary::class,
            'declared' => $declared,
            'observed' => $observed,
            'errors' => $errors,
            'unobserved_declared' => $unobservedDeclared,
        ];
    }

    /** @return list<string> */
    private function observedLevels(AssuranceVocabulary $vocabulary): array
    {
        $observed = [];
        foreach ($this->probeFacts() as $facts) {
            $level = $vocabulary->name($facts);
            if (! in_array($level, $observed, true)) {
                $observed[] = $level;
            }
        }

        usort(
            $observed,
            static fn (string $left, string $right): int => (AssuranceLevelComparator::isKnown($left) ? AssuranceLevelComparator::strength($left) : PHP_INT_MAX)
                <=> (AssuranceLevelComparator::isKnown($right) ? AssuranceLevelComparator::strength($right) : PHP_INT_MAX),
        );

        return $observed;
    }

    /** @return list<AssuranceFacts> */
    private function probeFacts(): array
    {
        $timestamp = new DateTimeImmutable('@0');
        $facts = [];

        foreach ([0, 1, 2] as $count) {
            $facts[] = new AssuranceFacts($count, FactorStrength::Knowledge, true, true, $timestamp);
        }
        foreach ([false, true] as $resistant) {
            $facts[] = new AssuranceFacts(1, FactorStrength::Knowledge, $resistant, true, $timestamp);
        }
        foreach ([false, true] as $multiFactor) {
            $facts[] = new AssuranceFacts(1, FactorStrength::Knowledge, true, $multiFactor, $timestamp);
        }
        foreach ([FactorStrength::Knowledge, FactorStrength::PossessionWeak, FactorStrength::Possession, FactorStrength::PossessionStrong] as $strongest) {
            $facts[] = new AssuranceFacts(1, $strongest, true, true, $timestamp);
        }
        foreach ([null, $timestamp] as $weakestSatisfiedAt) {
            $facts[] = new AssuranceFacts(1, FactorStrength::Knowledge, true, true, $weakestSatisfiedAt);
        }

        return $facts;
    }

    /**
     * @param list<string>|null $declared
     * @param list<string> $observed
     */
    private function derivability(string $level, ?array $declared, array $observed): string
    {
        if ($declared !== null) {
            return in_array($level, $declared, true) ? 'declared' : 'undeclared';
        }

        return in_array($level, $observed, true) ? 'observed' : 'undetermined';
    }
}
