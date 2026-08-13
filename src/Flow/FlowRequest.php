<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

/**
 * Everything the flow needs from a request, with nothing HTTP-shaped in it.
 *
 * No Request, Response or Session type crosses into the flow. That is what lets
 * one core drive both the JSON surface and Phase 3's adapters, and what makes
 * AuthFlow testable without booting a router.
 *
 * $boundContext is the DERIVED binding, never the raw host session ID — see
 * BindingDomain. Callers pass SessionBinding::for($id, BindingDomain::Attempt).
 */
final readonly class FlowRequest
{
    /**
     * @param  array<string, mixed>  $input
     */
    public function __construct(
        public ?string $handle,
        public ?string $action,
        public array $input,
        public string $boundContext,
        public ?string $clientIp = null,
        public ?string $clientUserAgent = null,
    ) {}

    /**
     * Read a string field, or null when it is absent or the wrong type.
     *
     * $input arrives from a request body; its shape is not to be trusted. Same
     * contract as VerificationRequest::string() in 2.2.
     */
    public function string(string $key): ?string
    {
        $value = $this->input[$key] ?? null;

        return is_string($value) ? $value : null;
    }
}
