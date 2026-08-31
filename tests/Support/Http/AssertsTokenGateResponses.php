<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Http;

use Illuminate\Testing\TestResponse;

/**
 * The token gate's wire contract, in one place.
 *
 * Extracted because it drifted twice: tenant mismatch and then group
 * installation both shipped asserting only a 401, which admits a step-up
 * challenge, a response body, or missing cache controls — none of which the
 * contract allows. Both were written in files that could not reach the
 * canonical tuple, so each reinvented a weaker assertion.
 *
 * Any test asserting a gate rejection uses this. A rejection that cannot be
 * expressed here is a rejection the contract has not actually specified.
 */
trait AssertsTokenGateResponses
{
    /**
     * The complete observable response, so a case cannot drift in a header the
     * per-case assertions forgot to name.
     *
     * @param  TestResponse<\Illuminate\Http\JsonResponse>  $response
     * @return array<string, mixed>
     */
    protected function responseTuple(TestResponse $response): array
    {
        return [
            'status' => $response->getStatusCode(),
            // A LIST, so exactly one header field is emitted. Two would let a
            // client read either, and a normalized lookup hides the second.
            'www-authenticate' => $response->headers->all('WWW-Authenticate'),
            'cache-control' => $response->headers->get('Cache-Control'),
            'vary' => $response->headers->get('Vary'),
            'body' => $response->getContent(),
        ];
    }

    /** @return array<string, mixed> */
    protected function canonicalRejection(): array
    {
        return [
            'status' => 401,
            'www-authenticate' => ['Bearer error="invalid_token"'],
            'cache-control' => 'no-store',
            'vary' => 'Authorization, Cookie',
            'body' => '',
        ];
    }

    /** The exact single line an RFC 9470 challenge must be. */
    protected function challengeLine(string $level, ?int $maxAge = null): string
    {
        $line = 'Bearer error="insufficient_user_authentication", '
            . 'error_description="A higher assurance level is required", '
            . 'acr_values="vouch:' . $level . '"';

        return $maxAge === null ? $line : $line . ', max_age="' . $maxAge . '"';
    }

    /** @return array<string, mixed> */
    protected function canonicalChallenge(string $level, ?int $maxAge = null): array
    {
        return [
            'status' => 401,
            'www-authenticate' => [$this->challengeLine($level, $maxAge)],
            'cache-control' => 'no-store',
            'vary' => 'Authorization, Cookie',
            'body' => '',
        ];
    }
}
