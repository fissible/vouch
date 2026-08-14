<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Attempts\Mutations\SingleUseMutation;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;

/**
 * Fails ONE nominated transition and delegates every other to the real store.
 *
 * A compare-and-swap loses when a concurrent request advanced the same attempt
 * first. That is an ordinary event, not an outage, and the branches handling it
 * are unreachable from a single-threaded test — which is why they were the last
 * uncovered code in AuthFlow.
 *
 * Failing the WHOLE store would not exercise them honestly: the flow would never
 * reach the transition under test, and the assertions would pass against a
 * fixture describing a database that had stopped answering. Nominating a single
 * target keeps everything before it real, so the attempt genuinely arrives at
 * the failure boundary in the state production would put it in.
 *
 * Every call is recorded, including the mutations offered with it. That is what
 * lets a test assert the flow did not go on to apply later mutations after a
 * refusal — the thing a returned value alone cannot show.
 */
final class TransitionSelectiveStore implements AttemptStore
{
    /** @var list<array{to: AttemptState, mutations: list<class-string>, outcome: TransitionOutcome}> */
    public array $calls = [];

    public function __construct(
        private readonly AttemptStore $inner,
        private readonly AttemptState $failAt,
    ) {}

    public function transition(
        AuthAttempt $attempt,
        AttemptState $to,
        SingleUseMutation ...$mutations,
    ): TransitionOutcome {
        $outcome = $to === $this->failAt
            // ConcurrentModification: a concurrent writer won the CAS. That is
            // the specific loss these branches exist for, not a generic refusal.
            ? TransitionOutcome::ConcurrentModification
            : $this->inner->transition($attempt, $to, ...$mutations);

        $this->calls[] = [
            'to' => $to,
            'mutations' => array_values(array_map(static fn (SingleUseMutation $m): string => $m::class, $mutations)),
            'outcome' => $outcome,
        ];

        return $outcome;
    }

    /** @return list<AttemptState> */
    public function attempted(): array
    {
        return array_map(
            static fn (array $call): AttemptState => $call['to'],
            $this->calls,
        );
    }
}
