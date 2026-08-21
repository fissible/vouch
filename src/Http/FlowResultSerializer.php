<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http;

use Fissible\Vouch\Flow\Authenticated;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowResult;
use Fissible\Vouch\Flow\RecoveryGraceStarted;
use Fissible\Vouch\Flow\UnknownFlowResult;
use Fissible\Vouch\Kernel\Screen\FactorOption;
use Fissible\Vouch\Kernel\Screen\FieldSpec;
use Fissible\Vouch\Kernel\Screen\RetryPolicy;
use Fissible\Vouch\Kernel\Screen\ScreenSpec;

/**
 * FlowResult to a JSON-ready envelope.
 *
 * The discriminator is the RESULT TYPE, not something inferred from screen
 * contents — that is the whole reason FlowResult is typed. A client reads an
 * outcome rather than guessing one.
 *
 * An unrecognised variant throws, matching FlowResultHandler. Serializing
 * "whatever screen we have" would emit a success-shaped envelope for a variant
 * nothing had acted on.
 */
final readonly class FlowResultSerializer
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(FlowResult $result, ?string $returnTo = null): array
    {
        return match (true) {
            $result instanceof Continuing => [
                'result' => 'continuing',
                'handle' => $result->handle,
                'screen' => $this->screen($result->screen),
            ],
            $result instanceof Authenticated => [
                'result' => 'authenticated',
                'handle' => null,
                'screen' => $this->screen($result->screen),
                // Already validated by IntendedDestination; the adapter must not
                // re-validate. A second validator is a second place to drift.
                'returnTo' => $returnTo,
            ],
            $result instanceof RecoveryGraceStarted => [
                'result' => 'recovery_grace',
                'handle' => null,
                'screen' => $this->screen($result->screen),
            ],
            default => throw UnknownFlowResult::for($result),
        };
    }

    /**
     * @return array<string, mixed>
     */
    private function screen(ScreenSpec $screen): array
    {
        return [
            'step' => $screen->step->value,
            'offeredFactors' => array_map(static fn (FactorOption $option): array => [
                'factorId' => $option->factorId,
                'label' => $option->label,
                'strength' => $option->strength->name,
                'isDefault' => $option->isDefault,
            ], $screen->offeredFactors),
            'fields' => array_map(static fn (FieldSpec $field): array => [
                'name' => $field->name,
                'type' => $field->type,
                'autocomplete' => $field->autocomplete,
                'maxLength' => $field->maxLength,
            ], $screen->fields),
            'challengePayload' => $screen->challengePayload,
            'errors' => $screen->errors,
            'retry' => $this->retry($screen->retry),
            'captchaRequired' => $screen->captchaRequired,
        ];
    }

    /**
     * @return array{attemptsRemaining: int|null, lockedUntil: string|null, retryAfter: string|null}|null
     */
    private function retry(?RetryPolicy $retry): ?array
    {
        if ($retry === null) {
            return null;
        }

        return [
            'attemptsRemaining' => $retry->attemptsRemaining,
            'lockedUntil' => $retry->lockedUntil?->format(DATE_ATOM),
            'retryAfter' => $retry->retryAfter?->format(DATE_ATOM),
        ];
    }
}
