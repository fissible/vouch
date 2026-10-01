<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Fissible\Vouch\Credentials\CredentialDriverFailureReport;
use Fissible\Vouch\Credentials\CredentialMutationResult;

/**
 * What a test needs to know about a mutation started from a deferred issuer
 * callback, captured at the moment it runs.
 *
 * Captured rather than inferred afterwards, because what separates this shape from
 * the frozen observer exclusions is not where the mutation came from but WHEN. An
 * observer runs inside the enclosing mutation, with the collector's depth elevated;
 * this runs after it, with depth unwound to the caller's.
 */
final class DeferredIssuerProbe
{
    public bool $fired = false;

    /**
     * Transaction level when the deferred callback ran.
     *
     * Necessary and not sufficient, which an earlier version of this class claimed
     * otherwise. Zero rules out a transactional Eloquent observer, but it does NOT
     * establish that the mutation which registered the callback has returned:
     * measured, with the service's transaction wrappers removed, afterCommit runs
     * inside the still-open during() of a top-level mutation and the level is
     * already zero there. So this is read alongside originatingMutationReturned,
     * which is the half that actually pins the window.
     */
    public ?int $transactionLevel = null;

    /**
     * Set by a factor hook that runs once the mutation which registered the deferred
     * callback has returned. Not an assertion target: by the time a test body reads
     * it, the hook has run whatever the ordering was.
     */
    public bool $originatingMutationReturned = false;

    /**
     * A SNAPSHOT of the field above, taken inside the deferred callback.
     *
     * This is the assertion target, and the distinction is load-bearing rather than
     * pedantic. Measured: asserting the mutable field at the end of the test passed
     * under a counter-implementation where the callback ran INSIDE the originating
     * mutation -- false at the callback, true by the time the assertion read it.
     * True here is what "depth has unwound" looks like from outside the collector;
     * false means the callback is still inside during(), where the frozen observer
     * exclusions govern instead of this shape.
     */
    public ?bool $returnedWhenCallbackRan = null;

    /** The mutation the callback started, so its own report can be asserted. */
    public ?CredentialMutationResult $nested = null;

    /**
     * The report from a collection the callback opened around one of its own
     * mutations.
     *
     * The inclusion half of the contract, in the deferred window. A fix that
     * suppresses reporting while deferred work runs keeps the enclosing caller clean
     * by silencing this too, and measured, that passes every exclusion case here.
     */
    public ?CredentialDriverFailureReport $ownCollection = null;

    /**
     * Every mutation the callback started, in order, for the cases that start more
     * than one.
     *
     * Sequential mutations inside ONE deferred callback are their own shape: the
     * first one's own driver callbacks run and finish before the second begins, so a
     * guard that merely tracks "am I inside deferred work" has already been cleared
     * by the time the second asks. Measured -- such a guard passes every single-
     * mutation case in this file.
     *
     * @var list<CredentialMutationResult>
     */
    public array $nestedMutations = [];
}
