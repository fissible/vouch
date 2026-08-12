<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\PHPStan;

use Pest\PendingCalls\TestCall;
use Pest\Support\HigherOrderCallables;
use PHPStan\Reflection\ClassReflection;
use PHPStan\Reflection\MethodReflection;
use PHPStan\Reflection\MethodsClassReflectionExtension;
use PHPStan\Reflection\ReflectionProvider;

/**
 * Teaches PHPStan that `Pest\PendingCalls\TestCall::expect()` resolves at
 * runtime through `Pest\Support\HigherOrderCallables::expect()`, one of
 * `TestCall`'s declared `@mixin HigherOrderCallables|TestCase|Testable`
 * types. PHPStan's own mixin resolution does not walk that particular union
 * far enough to find `expect()`, so without this extension every
 * `arch(...)->expect(...)` call — used verbatim by every arch test in this
 * package — is reported as calling an undefined method, even though it
 * always succeeds when the suite actually runs.
 *
 * This resolves the method via real PHPStan reflection at analysis time,
 * borrowing the genuine, already-reflectable `HigherOrderCallables::expect()`
 * native method, rather than re-declaring a parallel signature (e.g. via a
 * stub file's `@method` tag) that could silently drift from the real one.
 * A stub-file `@method` approach was tried first and rejected: PHPStan
 * cannot resolve any Composer-autoloaded class (only PHP built-ins) inside
 * a stub file's `@method` return type, so it isn't usable here.
 */
final class PestTestCallMixinExtension implements MethodsClassReflectionExtension
{
    public function __construct(
        private readonly ReflectionProvider $reflectionProvider,
    ) {
    }

    public function hasMethod(ClassReflection $classReflection, string $methodName): bool
    {
        return $classReflection->getName() === TestCall::class && $methodName === 'expect';
    }

    public function getMethod(ClassReflection $classReflection, string $methodName): MethodReflection
    {
        return $this->reflectionProvider
            ->getClass(HigherOrderCallables::class)
            ->getNativeMethod('expect');
    }
}
