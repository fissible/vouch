<?php

declare(strict_types=1);

namespace Vendor\Probe;

/**
 * The plain bypass: a token minted with no assurance evaluation at all.
 *
 * This is §6.2's live example rather than an invented one -- sluice called
 * createToken() in exactly this shape, which is why the audit exists.
 */
final class DirectIssuer
{
    public function mint(User $user): string
    {
        return $user->createToken('api')->plainTextToken;
    }

    public function mintFromLookup(): string
    {
        // A chained call on a static entry point. The receiver is not a
        // variable the lexer has to track, so this resolves.
        return User::find(1)->createToken('api')->plainTextToken;
    }
}
