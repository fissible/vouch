<?php

declare(strict_types=1);

namespace Fissible\Vouch\Verification;

use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Contracts\RandomSource;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthIdentifierVerification;
use Fissible\Vouch\Throttle\IssuancePermission;
use Fissible\Vouch\Throttle\ThrottleKey;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Hash;
use Psr\Clock\ClockInterface;

/** Identifier-control ceremony: never creates a login attempt or session. */
final readonly class IdentifierVerifier
{
    public function __construct(
        private AuthThrottleStore $throttles,
        private ThrottleKey $keys,
        private IdentifierVerificationOutbox $outbox,
        private Connection $connection,
        private DatabaseTime $time,
        private ClockInterface $clock,
        private int $ttlSeconds,
        private RandomSource $random,
    ) {
    }

    public function request(IdentifierVerificationRequest $request): void
    {
        $identifier = AuthIdentifier::query()->where('type', $request->type)
            ->where('value', $request->submittedIdentifier)
            ->first();

        $this->issue($request, $identifier);
    }

    /**
     * Issue the same charged, durable ceremony shape without looking up a
     * target.  Callers use this when revealing a known identifier would be an
     * enumeration oracle; the worker deletes this decoy before provider I/O.
     */
    public function requestDecoy(IdentifierVerificationRequest $request): void
    {
        $this->issue($request, null);
    }

    private function issue(IdentifierVerificationRequest $request, ?AuthIdentifier $identifier): void
    {
        $this->outbox->assertReady();

        if ($this->throttles->permitIssuance(
            $this->keys->ceremony($request->submittedIdentifier, $request->tenantId),
        ) === IssuancePermission::Refused) {
            return;
        }

        $this->outbox->issue($request, $identifier, $this->code(), $this->ttlSeconds);
    }

    public function redeem(IdentifierVerificationRequest $request, string $code): IdentifierVerificationOutcome
    {
        if ($code === '') {
            return IdentifierVerificationOutcome::Refused;
        }

        return $this->connection->transaction(function () use ($request, $code): IdentifierVerificationOutcome {
            /*
             * Lock the verification before checking or consuming it, then lock
             * the identifier before changing verified_at. Both rows must stay
             * stable for the full single-use transition, otherwise concurrent
             * redeems could each observe a live code or race the target update.
             */
            $verification = AuthIdentifierVerification::query()
                ->where('identifier_type', $request->type)
                ->where('identifier_value', $request->submittedIdentifier)
                ->whereNull('consumed_at')
                ->where('expires_at', '>', $this->clock->now())
                ->latest('id')
                ->lockForUpdate()
                ->first();

            /*
             * Check the code before refusing a decoy. The comparison preserves
             * the ceremony's known-versus-unknown work shape; a decoy can never
             * succeed, but must not become a cheaper existence oracle.
             */
            if (! $verification instanceof AuthIdentifierVerification
                || ! Hash::check($code, $verification->code_hash)
                || $verification->is_decoy) {
                return IdentifierVerificationOutcome::Refused;
            }

            $identifier = AuthIdentifier::query()->where('type', $request->type)
                ->where('value', $request->submittedIdentifier)
                ->lockForUpdate()
                ->first();

            if (! $identifier instanceof AuthIdentifier) {
                return IdentifierVerificationOutcome::Refused;
            }

            AuthIdentifierVerification::query()->whereKey($verification->id)
                ->whereNull('consumed_at')
                ->update(['consumed_at' => $this->time->now()]);

            AuthIdentifier::query()->whereKey($identifier->id)
                ->update(['verified_at' => $this->time->now()]);

            return IdentifierVerificationOutcome::Verified;
        });
    }

    /**
     * Fixed at six digits, unlike OtpFactor's configurable length, so this
     * generator cannot produce the empty code that would authenticate an empty
     * submission. RandomSource keeps the CSPRNG range injectable and testable.
     */
    private function code(): string
    {
        $code = '';

        for ($i = 0; $i < 6; $i++) {
            $code .= (string) $this->random->int(0, 9);
        }

        return $code;
    }
}
