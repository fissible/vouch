<?php

declare(strict_types=1);

namespace Fissible\Vouch\Notifications;

use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthChallengeOutbox;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Hash;
use InvalidArgumentException;
use RuntimeException;

/** Atomically persists one verifiable challenge and its encrypted delivery. */
final readonly class OtpChallengeOutbox
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

    public function issue(
        ChallengeRequest $request,
        string $factorId,
        string $code,
        int $ttlSeconds,
        ?AuthIdentifier $identifier,
    ): AuthChallenge {
        $target = null;

        if ($identifier instanceof AuthIdentifier) {
            if ($identifier->verified_at === null) {
                throw new InvalidArgumentException(sprintf(
                    'Identifier %d is not verified and cannot receive an %s code.',
                    $identifier->id,
                    $factorId,
                ));
            }

            $target = [
                'id' => $identifier->id,
                'user_id' => $identifier->user_id,
                'type' => $identifier->type,
                'value' => $identifier->value,
                'verified_at' => $identifier->verified_at->toISOString(),
            ];
        }

        /** @var array{AuthChallenge, AuthChallengeOutbox} $issued */
        $issued = $this->connection->transaction(function () use (
            $request,
            $factorId,
            $code,
            $ttlSeconds,
            $target,
        ): array {
            // This lock makes concurrent resends agree on the same pending row
            // instead of each minting a replacement code.
            $attempt = AuthAttempt::query()->whereKey($request->attempt->id)->lockForUpdate()->first();

            if (! $attempt instanceof AuthAttempt) {
                throw new RuntimeException('The attempt vanished before challenge issuance.');
            }

            if ($request->reusePending) {
                $existing = $this->pending(
                    $attempt->id,
                    $factorId,
                    $request->credential?->id,
                    $request->decoy,
                );

                if ($existing !== null) {
                    return $existing;
                }
            }

            $expiresAt = $this->time->deadline($ttlSeconds);

            $challenge = AuthChallenge::create([
                'attempt_id' => $attempt->id,
                'credential_id' => $request->credential?->id,
                'factor_type' => $factorId,
                'is_decoy' => $request->decoy,
                'code_hash' => Hash::make($code),
                'bound_ip' => $request->clientIp,
                'bound_user_agent' => $request->clientUserAgent,
                'expires_at' => $expiresAt,
            ]);

            $outbox = AuthChallengeOutbox::create([
                'opaque_id' => bin2hex(random_bytes(32)),
                'challenge_id' => $challenge->id,
                'payload' => [
                    'target' => $target,
                    'code' => $code,
                    'decoy' => $request->decoy,
                ],
                'status' => OtpOutboxStatus::Pending->value,
                'expires_at' => $expiresAt,
            ]);

            return [$challenge, $outbox];
        });

        $this->dispatcher->dispatch($issued[1]);

        return $issued[0];
    }

    /** @return array{AuthChallenge, AuthChallengeOutbox}|null */
    private function pending(
        int $attemptId,
        string $factorId,
        ?int $credentialId,
        bool $decoy,
    ): ?array {
        $challengeQuery = AuthChallenge::query()
            ->where('attempt_id', $attemptId)
            ->where('factor_type', $factorId)
            ->where('is_decoy', $decoy)
            ->whereNull('consumed_at');

        $credentialId === null
            ? $challengeQuery->whereNull('credential_id')
            : $challengeQuery->where('credential_id', $credentialId);

        $challenge = $challengeQuery->latest('id')->first();

        if (! $challenge instanceof AuthChallenge) {
            return null;
        }

        $outbox = AuthChallengeOutbox::query()
            ->where('challenge_id', $challenge->id)
            ->where('status', OtpOutboxStatus::Pending->value)
            ->where('expires_at', '>', $this->time->now())
            ->first();

        return $outbox instanceof AuthChallengeOutbox
            ? [$challenge, $outbox]
            : null;
    }
}
