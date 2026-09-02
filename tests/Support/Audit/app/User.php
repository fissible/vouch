<?php

declare(strict_types=1);

namespace Vendor\Probe;

/** Stands in for the host's user model, so the fixture app typechecks. */
final class User
{
    public static function find(int $id): self
    {
        return new self();
    }

    public function createToken(string $name): NewToken
    {
        return new NewToken();
    }
}
