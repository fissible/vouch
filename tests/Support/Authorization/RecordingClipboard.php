<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Authorization;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection as BaseCollection;
use Silber\Bouncer\Contracts\Clipboard;

/**
 * A Bouncer clipboard that records the calls made to it and holds no opinion.
 *
 * `checkGetId()` returning null is Bouncer's "no opinion" value, so its Gate
 * hook defers and the Gate goes on to the ability callback. That is what lets
 * a single probe distinguish the two dispatch paths without a database: a
 * Gate-routed `can()` reaches the ability, a Bouncer-routed one never does.
 */
final class RecordingClipboard implements Clipboard
{
    /** @var list<string> */
    public array $calls = [];

    public function check(Model $authority, $ability, $model = null): bool
    {
        $this->calls[] = 'clipboard:check';

        return false;
    }

    public function checkGetId(Model $authority, $ability, $model = null): int|bool|null
    {
        $this->calls[] = 'clipboard:checkGetId';

        return null;
    }

    /**
     * @param  array<int, string>|string  $roles
     */
    public function checkRole(Model $authority, $roles, $boolean = 'or'): bool
    {
        $this->calls[] = 'clipboard:checkRole';

        return false;
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
