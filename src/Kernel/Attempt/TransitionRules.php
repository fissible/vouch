<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Attempt;

final class TransitionRules
{
    private const TERMINAL = [
        AttemptState::Authenticated->value,
        AttemptState::RegistrationRequired->value,
        AttemptState::Failed->value,
        AttemptState::Locked->value,
    ];

    /**
     * Legal forward transitions. Failed and Locked are reachable from any live
     * state and are added at check time rather than repeated in every row.
     *
     * @var array<string, list<AttemptState>>
     */
    private const FORWARD = [
        AttemptState::Initiated->value => [
            AttemptState::Identified,
        ],
        AttemptState::Identified->value => [
            AttemptState::FactorPending,
            AttemptState::RegistrationRequired,
        ],
        AttemptState::FactorPending->value => [
            AttemptState::FactorSatisfied,
        ],
        AttemptState::FactorSatisfied->value => [
            AttemptState::FactorPending,
            AttemptState::Authenticated,
        ],
    ];

    public function allows(AttemptState $from, AttemptState $to): bool
    {
        if ($from === $to) {
            return false;
        }

        if ($this->isTerminal($from)) {
            return false;
        }

        if ($to === AttemptState::Failed || $to === AttemptState::Locked) {
            return true;
        }

        return in_array($to, self::FORWARD[$from->value] ?? [], strict: true);
    }

    public function isTerminal(AttemptState $state): bool
    {
        return in_array($state->value, self::TERMINAL, strict: true);
    }
}
