<?php

declare(strict_types=1);

use Vendor\Probe\User;

/*
 * Issuance from a route file rather than a class.
 *
 * The default scan paths are `app` and `routes` precisely because this shape
 * exists: a closure route that mints directly is not reachable from an autoload
 * root, which is why the paths are configured rather than derived.
 */
return static function (User $user): string {
    return $user->createToken('route-minted')->plainTextToken;
};
