<?php

declare(strict_types=1);

namespace Vendor\Probe;

/** Constructs a lexer cannot resolve. Each must be NAMED, never dropped. */
final class DynamicIssuer
{
    public function dynamicMethod(User $user, string $method): mixed
    {
        // The method name is not knowable statically. It may or may not mint.
        return $user->{$method}('api');
    }

    /** @param class-string<User> $class */
    public function dynamicClass(string $class): mixed
    {
        return $class::find(1);
    }

    public function indirect(User $user): mixed
    {
        return call_user_func([$user, 'createToken'], 'api');
    }
}
