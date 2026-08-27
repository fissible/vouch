<?php

declare(strict_types=1);

namespace Fissible\Vouch\Authorization;

use Illuminate\Auth\Middleware\Authorize;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;

/** Reads the host's authorization declarations instead of requiring a duplicate Vouch one. */
final readonly class RouteAbilityScanner
{
    private const SPATIE_PERMISSION = 'Spatie\\Permission\\Middleware\\PermissionMiddleware';
    private const SPATIE_ROLE_OR_PERMISSION = 'Spatie\\Permission\\Middleware\\RoleOrPermissionMiddleware';

    public function __construct(private Router $router) {}

    /** @return list<string> */
    public function abilitiesFor(Route $route): array
    {
        $abilities = [];
        foreach (array_values(array_unique($route->gatherMiddleware())) as $middleware) {
            [$name, $parameters] = array_pad(explode(':', $middleware, 2), 2, null);
            // Laravel aliases `can`; Spatie intentionally leaves its aliases to
            // the host. The latter names remain conventional declarations, but
            // a renamed host alias is recognised only after table resolution.
            $class = match ($name) {
                'can' => Authorize::class,
                'permission' => self::SPATIE_PERMISSION,
                'role_or_permission' => self::SPATIE_ROLE_OR_PERMISSION,
                default => $this->router->getMiddleware()[$name] ?? $name,
            };
            if (! is_string($class) || ! is_string($parameters)) {
                continue;
            }
            $names = $this->namesFor($class, $parameters);
            foreach ($names as $ability) {
                if ($ability !== '' && ! in_array($ability, $abilities, true)) {
                    $abilities[] = $ability;
                }
            }
        }
        return $abilities;
    }

    /** @return list<string> */
    private function namesFor(string $class, string $parameters): array
    {
        $first = explode(',', $parameters, 2)[0];
        if ($class === Authorize::class) {
            return $this->trimmed([$first]);
        }
        // The aliases are meaningful only when Spatie is installed. Guarding
        // the optional package keeps a conventional host alias from causing
        // Vouch to claim it understands middleware it cannot execute.
        if ((class_exists(self::SPATIE_PERMISSION) && $class === self::SPATIE_PERMISSION)
            || (class_exists(self::SPATIE_ROLE_OR_PERMISSION) && $class === self::SPATIE_ROLE_OR_PERMISSION)) {
            return $this->trimmed(explode('|', $first));
        }
        return [];
    }

    /**
     * @param list<string> $values
     * @return list<string>
     */
    private function trimmed(array $values): array
    {
        $names = [];
        foreach ($values as $value) {
            $value = trim($value);
            if ($value !== '') {
                $names[] = $value;
            }
        }
        return $names;
    }
}
