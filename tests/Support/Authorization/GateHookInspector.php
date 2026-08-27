<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Authorization;

use Closure;
use Illuminate\Auth\Access\Gate;
use ReflectionFunction;
use ReflectionProperty;

/**
 * Reads the Gate's registered before/after callbacks and names their origin.
 *
 * Task 5a probe 1 asks which hooks actually exist at runtime and in what
 * order. Both properties are protected and there is no public accessor, so
 * reflection is the only way to observe registration rather than infer it
 * from dispatch behaviour.
 */
final class GateHookInspector
{
    /**
     * @return list<string>
     */
    public static function before(Gate $gate): array
    {
        return self::describe(self::read($gate, 'beforeCallbacks'));
    }

    /**
     * @return list<string>
     */
    public static function after(Gate $gate): array
    {
        return self::describe(self::read($gate, 'afterCallbacks'));
    }

    /**
     * @return list<callable>
     */
    private static function read(Gate $gate, string $property): array
    {
        $reflection = new ReflectionProperty(Gate::class, $property);

        /** @var list<callable> $callbacks */
        $callbacks = $reflection->getValue($gate);

        return $callbacks;
    }

    /**
     * Name a callback by the class its closure was written in.
     *
     * The scope class is the declaring class of the method that created the
     * closure, which is stable across package versions in a way the file path
     * is not. A callback with no scope (a top-level closure, as a host app or
     * a test writes) is reported by file and line instead.
     *
     * @param  list<callable>  $callbacks
     * @return list<string>
     */
    private static function describe(array $callbacks): array
    {
        $described = [];

        foreach ($callbacks as $callback) {
            if (! $callback instanceof Closure) {
                $described[] = 'non-closure:' . get_debug_type($callback);

                continue;
            }

            $function = new ReflectionFunction($callback);
            $scope = $function->getClosureScopeClass();

            $described[] = $scope instanceof \ReflectionClass
                ? $scope->getName()
                : sprintf('closure@%s:%d', basename((string) $function->getFileName()), (int) $function->getStartLine());
        }

        return $described;
    }
}
