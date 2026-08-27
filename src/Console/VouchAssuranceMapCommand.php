<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

use Fissible\Vouch\Authorization\AssuranceRequirements;
use Fissible\Vouch\Http\Middleware\RequireAbilityAssurance;
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
    public function handle(AssuranceRequirements $requirements, Router $router): int
    {
        $declared = AssuranceRequirements::declaredFrom(config('vouch.declared_abilities'));
        $gate = Gate::abilities();
        $rows = [];
        $unknown = [];
        foreach ($requirements->all() as $ability => $level) {
            $source = array_key_exists($ability, $gate) ? 'gate' : (in_array($ability, $declared, true) ? 'declared' : 'unknown');
            $rows[] = compact('ability', 'level', 'source');
            if ($source === 'unknown') {
                $unknown[] = $ability;
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
        ];
        if ($this->option('json') === true) {
            $this->line(json_encode($report, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        } else {
            $this->table(
                ['Ability', 'Level', 'Source'],
                array_map(static fn (array $row): array => [$row['ability'], $row['level'], $row['source']], $rows),
            );
            $this->components->info('Unknown abilities: ' . ($unknown === [] ? 'none' : implode(', ', $unknown)) . '.');
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
}
