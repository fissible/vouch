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

    /**
     * A variable class calling an ISSUANCE-named method.
     *
     * The bar is "may be an issuance call", not "is dynamic": an earlier
     * version of this fixture called an unrelated method, which would have
     * pressured the scanner into flagging every variable-class call in a host
     * codebase and burying the findings that matter.
     *
     * @param class-string<StaticIssuer> $class
     */
    public function dynamicClass(string $class): mixed
    {
        return $class::createToken('api');
    }

    public function indirect(User $user): mixed
    {
        return call_user_func([$user, 'createToken'], 'api');
    }

    /** A relative of call_user_func, and just as opaque. */
    public function indirectArray(User $user): mixed
    {
        return call_user_func_array([$user, 'createToken'], ['api']);
    }
}
