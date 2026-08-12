<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Screen;

final readonly class FieldSpec
{
    public function __construct(
        public string $name,
        public string $type,
        public string $autocomplete,
        public ?int $maxLength,
    ) {}
}
