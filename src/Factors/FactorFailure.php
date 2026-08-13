<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

/**
 * Why a verification did not succeed — reported TRUTHFULLY and never pre-redacted.
 *
 * The kernel's ErrorShaper is the only response-facing boundary and decides
 * disclosure under the tenant's enumeration posture. A driver that self-censored
 * would make the strict-posture guarantee unverifiable, because two components
 * would each be deciding what a response may reveal and neither would own it.
 *
 * BindingMismatch extends the spec's five-case list deliberately: a code
 * submitted from the wrong IP is a different fact from a wrong code, and
 * deciding those are equivalent is a disclosure judgement.
 */
enum FactorFailure: string
{
    /** No usable credential of this type exists for the user. */
    case NoCredential = 'no_credential';

    /** The secret did not match. */
    case Mismatch = 'mismatch';

    /** The challenge or code is past its lifetime. */
    case Expired = 'expired';

    /** The challenge or code was already used. */
    case Consumed = 'consumed';

    /** The submitted input was the wrong shape to be a code at all. */
    case Malformed = 'malformed';

    /** The request context did not match what the challenge was bound to. */
    case BindingMismatch = 'binding_mismatch';
}
