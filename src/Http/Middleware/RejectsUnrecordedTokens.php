<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http\Middleware;

use Closure;
use Fissible\Vouch\Assurance\AssuranceRequirement;
use Fissible\Vouch\Assurance\AssuranceComparison;
use Fissible\Vouch\Assurance\EvidenceComparator;
use Fissible\Vouch\Contracts\TenantResolver;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Tokens\TokenIssuerRegistry;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;

/**
 * Applies recorded assurance only after an issuer authenticated this request
 * with one of its tokens.  In particular, this deliberately does not inspect
 * Authorization: Sanctum may have selected a cookie-authenticated principal.
 */
final readonly class RejectsUnrecordedTokens
{
    public function __construct(
        private TokenIssuerRegistry $issuers,
        private TokenAssuranceRecord $records,
        private EvidenceComparator $evidenceComparator,
        private ClockInterface $clock,
        private TenantResolver $tenants,
    ) {}

    public function handle(Request $request, Closure $next, string $required = 'aal1', ?string $maxAge = null): Response
    {
        $mode = $this->mode();
        $requirement = AssuranceRequirement::from($maxAge === null ? $required : [
            'level' => $required,
            'max_age' => $maxAge,
        ]);

        $token = $this->issuers->resolveForRequest($request);
        if ($token === null) {
            return $next($request);
        }

        $read = $this->records->read($token);
        $comparison = $this->evidenceComparator->compare(
            $read,
            $requirement,
            $this->clock,
            $this->tenantId(),
        );

        if ($comparison->outcome->isSufficient()) {
            return $next($request);
        }

        if ($mode === 'observe') {
            if (! $request->attributes->has('vouch.token_gate.observed')) {
                $request->attributes->set('vouch.token_gate.observed', true);
                Log::warning('Vouch token gate would refuse a token.', [
                    'issuer_key' => $token->issuerKey,
                    'token_key' => $token->tokenKey,
                    'reason' => $this->observationReason($comparison),
                ]);
            }

            return $next($request);
        }

        return $this->refusal($comparison, $requirement);
    }

    private function mode(): string
    {
        $value = config('vouch.token_gate.mode');

        if ($value === 'observe' || $value === 'enforce') {
            return $value;
        }

        throw new InvalidArgumentException(sprintf(
            'Configuration "vouch.token_gate.mode" must be exactly "observe" or "enforce"; got %s.',
            $this->describe($value),
        ));
    }

    private function observationReason(AssuranceComparison $comparison): string
    {
        return $comparison->reason === \Fissible\Vouch\Assurance\AssuranceReason::NoAssuranceRecord
            ? 'no_assurance_record'
            : 'insufficient_assurance';
    }

    private function describe(mixed $value): string
    {
        return match (true) {
            $value === '' => 'an empty string',
            is_string($value) => 'string "' . $value . '"',
            is_int($value) => (string) $value,
            $value === null => 'null',
            default => get_debug_type($value),
        };
    }

    private function tenantId(): ?string
    {
        return $this->tenants->currentTenantId();
    }

    private function refusal(AssuranceComparison $comparison, AssuranceRequirement $requirement): Response
    {
        if ($comparison->outcome !== \Fissible\Vouch\Assurance\AssuranceOutcome::InsufficientLevel
            && $comparison->outcome !== \Fissible\Vouch\Assurance\AssuranceOutcome::InsufficientRecency) {
            return $this->response('Bearer error="invalid_token"');
        }

        $line = 'Bearer error="insufficient_user_authentication", '
            . 'error_description="A higher assurance level is required", '
            . 'acr_values="vouch:' . $requirement->level . '"';
        $maxAge = $requirement->maxAgeSeconds();
        if ($maxAge !== null) {
            $line .= ', max_age="' . $maxAge . '"';
        }

        return $this->response($line);
    }

    private function response(string $authenticate): Response
    {
        /*
         * ResponseHeaderBag deliberately appends `private` to cache directives
         * that lack an explicit visibility rule. The token-gate wire contract
         * is exactly `no-store`, so use a bag that preserves that directive.
         */
        $headers = new class([
            'WWW-Authenticate' => $authenticate,
            'Cache-Control' => 'no-store',
            'Vary' => 'Authorization, Cookie',
        ]) extends ResponseHeaderBag {
            protected function computeCacheControlValue(): string
            {
                return $this->getCacheControlHeader();
            }
        };

        return new Response('', 401, $headers);
    }
}
