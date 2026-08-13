<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;

/**
 * Everything a driver needs to verify a submission.
 *
 * The IP and user agent are not optional decoration. The challenge records
 * bound_ip and bound_user_agent at delivery, and a driver with no request
 * context cannot compare them — so the binding would be written to the database
 * and never checked. A guard that is stored but never evaluated is not a guard.
 *
 * $input stays an untyped array in v1: enrollment and verification payloads are
 * genuinely heterogeneous across drivers, and each validates its own at entry.
 * Typed DTOs are recorded as a follow-up in spec §7.
 */
final readonly class VerificationRequest
{
    /**
     * @param  array<string, mixed>  $input
     */
    public function __construct(
        public AuthAttempt $attempt,
        public array $input,
        public ?AuthCredential $credential = null,
        public ?AuthChallenge $challenge = null,
        public ?string $clientIp = null,
        public ?string $clientUserAgent = null,
    ) {}

    /**
     * Read a string field, or null when it is absent or the wrong type.
     *
     * Drivers must not trust $input's shape: it arrives from a request body.
     */
    public function string(string $key): ?string
    {
        $value = $this->input[$key] ?? null;

        return is_string($value) ? $value : null;
    }
}
