<?php

declare(strict_types=1);

namespace Fissible\Vouch\Verification;

use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthIdentifierVerification;
use Fissible\Vouch\Models\AuthIdentifierVerificationOutbox;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Notifications\OtpQueueDispatcher;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Hash;

/** Persists an attempt-independent identifier-control code and encrypted send. */
final readonly class IdentifierVerificationOutbox
{
    public function __construct(
        private Connection $connection,
        private OtpQueueDispatcher $dispatcher,
        private DatabaseTime $time,
    ) {}

    public function assertReady(): void
    {
        $this->dispatcher->assertAsynchronous();
    }

    public function issue(IdentifierVerificationRequest $request, ?AuthIdentifier $identifier, string $code, int $ttlSeconds): void
    {
        $target = $identifier instanceof AuthIdentifier ? [
            'id' => $identifier->id,
            'user_id' => $identifier->user_id,
            'type' => $identifier->type,
            'value' => $identifier->value,
            'verified_at' => $identifier->verified_at?->toISOString(),
        ] : null;

        /** @var AuthIdentifierVerificationOutbox $outbox */
        $outbox = $this->connection->transaction(function () use ($request, $identifier, $code, $ttlSeconds, $target): AuthIdentifierVerificationOutbox {
            $expiresAt = $this->time->deadline($ttlSeconds);
            $verification = AuthIdentifierVerification::create([
                'identifier_type' => $request->type,
                'identifier_value' => $request->submittedIdentifier,
                'code_hash' => Hash::make($code),
                'is_decoy' => ! $identifier instanceof AuthIdentifier,
                'expires_at' => $expiresAt,
            ]);

            return AuthIdentifierVerificationOutbox::create([
                'opaque_id' => bin2hex(random_bytes(32)),
                'verification_id' => $verification->id,
                'payload' => ['target' => $target, 'code' => $code, 'decoy' => ! $identifier instanceof AuthIdentifier],
                'status' => OtpOutboxStatus::Pending->value,
                'expires_at' => $expiresAt,
            ]);
        });

        $this->dispatcher->dispatchVerification($outbox);
    }
}
