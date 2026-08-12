<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Screen;

final readonly class ScreenSpec
{
    /**
     * @param list<FactorOption>        $offeredFactors
     * @param list<FieldSpec>           $fields
     * @param array<string, mixed>|null $challengePayload
     * @param list<string>              $errors
     */
    public function __construct(
        public AuthStep $step,
        public array $offeredFactors,
        public array $fields,
        public ?array $challengePayload,
        public array $errors,
        public ?RetryPolicy $retry,
    ) {}
}
