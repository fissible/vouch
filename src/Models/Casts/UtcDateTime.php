<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models\Casts;

use DateTimeInterface;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * SQLite stores Laravel datetimes without an offset. Interpret this assurance
 * anchor as UTC on every read so an authorization decision cannot depend on
 * PHP's process timezone.
 *
 * @implements CastsAttributes<Carbon|null, Carbon|DateTimeInterface|string|null>
 */
final class UtcDateTime implements CastsAttributes
{
    public function get(Model $model, string $key, mixed $value, array $attributes): ?Carbon
    {
        if ($value === null) {
            return null;
        }

        if ($value instanceof DateTimeInterface) {
            return Carbon::instance($value)->utc();
        }

        if (! is_string($value)) {
            throw new \UnexpectedValueException('The database datetime value must be a string or DateTimeInterface.');
        }

        return Carbon::createFromFormat($model->getDateFormat(), $value, 'UTC');
    }

    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        return Carbon::parse($value)->utc()->format($model->getDateFormat());
    }
}
