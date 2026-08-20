<?php

declare(strict_types=1);

namespace Fissible\Vouch\Notifications;

use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthChallengeOutbox;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Support\DatabaseTime;
use Throwable;

/** Executes one outbox delivery without ever regenerating its code. */
final readonly class OtpOutboxDelivery
{
    public function __construct(
        private OtpDelivery $delivery,
        private DatabaseTime $time,
    ) {}

    public function deliver(string $opaqueId): void
    {
        $outbox = AuthChallengeOutbox::query()
            ->where('opaque_id', $opaqueId)
            ->where('status', OtpOutboxStatus::Pending->value)
            ->first();

        if (! $outbox instanceof AuthChallengeOutbox) {
            // Swept or already-terminal rows are normal under at-least-once
            // queueing. Retrying them creates noise without useful work.
            return;
        }

        if ($this->expired($outbox)) {
            $this->terminalize($opaqueId, OtpOutboxFailureReason::ExpiredUndelivered);

            return;
        }

        $payload = $outbox->payload;

        if ($payload === null || $payload['decoy']) {
            // A decoy performs the same durable request-side work but must never
            // contact a provider or be counted as a delivery failure.
            $outbox->delete();

            return;
        }

        $identifier = $this->target($payload);

        if (! $identifier instanceof AuthIdentifier) {
            $this->terminalize($opaqueId, OtpOutboxFailureReason::TargetUnavailable);

            return;
        }

        try {
            $this->delivery->deliver(
                $identifier,
                $payload['code'],
                $outbox->expires_at->toDateTimeImmutable(),
            );
        } catch (PermanentOtpDeliveryFailure) {
            $this->terminalize($opaqueId, OtpOutboxFailureReason::ProviderRejected);

            return;
        } catch (Throwable) {
            if ($this->expired($outbox)) {
                $this->terminalize($opaqueId, OtpOutboxFailureReason::ExpiredUndelivered);

                return;
            }

            throw new TransientOtpDeliveryFailure(
                'OTP delivery failed transiently; the encrypted outbox row remains pending.',
            );
        }

        AuthChallengeOutbox::query()
            ->where('opaque_id', $opaqueId)
            ->where('status', OtpOutboxStatus::Pending->value)
            ->update([
                'payload' => null,
                'status' => OtpOutboxStatus::Delivered->value,
                'delivered_at' => $this->time->now(),
            ]);
    }

    public function terminalize(
        string $opaqueId,
        OtpOutboxFailureReason $reason = OtpOutboxFailureReason::ExpiredUndelivered,
    ): void
    {
        AuthChallengeOutbox::query()
            ->where('opaque_id', $opaqueId)
            ->where('status', OtpOutboxStatus::Pending->value)
            ->update([
                'payload' => null,
                'status' => OtpOutboxStatus::Undeliverable->value,
                'undeliverable_at' => $this->time->now(),
                'failure_reason' => $reason->value,
            ]);
    }

    /** @phpstan-impure Database time can cross the deadline during provider I/O. */
    private function expired(AuthChallengeOutbox $outbox): bool
    {
        return AuthChallengeOutbox::query()
            ->whereKey($outbox->id)
            ->where('expires_at', '<=', $this->time->now())
            ->exists();
    }

    /**
     * Rehydrate the immutable delivery target captured at issuance time.
     *
     * @param array{target: array{id: int, user_id: int, type: string, value: string, verified_at: string}|null, code: string, decoy: bool} $payload
     */
    private function target(array $payload): ?AuthIdentifier
    {
        $target = $payload['target'];

        if ($target === null) {
            return null;
        }

        return new AuthIdentifier($target);
    }
}
