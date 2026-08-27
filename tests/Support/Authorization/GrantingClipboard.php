<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Authorization;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection as BaseCollection;
use Silber\Bouncer\Contracts\Clipboard;

/**
 * A Bouncer clipboard that grants everything.
 *
 * Bouncer reads a grant as a truthy ability id from `checkGetId()`, so the
 * value has to be an id rather than `true`.
 */
final class GrantingClipboard implements Clipboard
{
    public function check(Model $authority, $ability, $model = null): bool
    {
        return true;
    }

    public function checkGetId(Model $authority, $ability, $model = null): int
    {
        return 1;
    }

    /**
     * @param  array<int, string>|string  $roles
     */
    public function checkRole(Model $authority, $roles, $boolean = 'or'): bool
    {
        return true;
    }

    /**
     * @return BaseCollection<int, mixed>
     */
    public function getRoles(Model $authority): BaseCollection
    {
        return new BaseCollection;
    }

    /**
     * @return Collection<int, Model>
     */
    public function getAbilities(Model $authority, $allowed = true): Collection
    {
        return new Collection;
    }

    /**
     * @return Collection<int, Model>
     */
    public function getForbiddenAbilities(Model $authority): Collection
    {
        return new Collection;
    }
}
