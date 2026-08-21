<?php

declare(strict_types=1);

namespace Fissible\Vouch\Notifications;

use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Delivery\DeliveryEconomicsRequest;
use Fissible\Vouch\Delivery\DeliveryReservationDecision;
use Fissible\Vouch\Delivery\SmsCountryNormalizer;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthChallengeOutbox;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Support\DatabaseTime;
use Throwable;

/** Executes one outbox delivery without ever regenerating its code. */
final readonly class OtpOutboxDelivery
{
    public function __construct(
        private OtpDelivery $delivery,
        private DeliveryEconomics $economics,
        private SmsCountryNormalizer $normalizer,
        private DatabaseTime $time,
        /** @var array{email: int, sms: int} */
        private array $costs,
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

        $challenge = AuthChallenge::query()->whereKey($outbox->challenge_id)->first();
        $attempt = $challenge instanceof AuthChallenge
            ? AuthAttempt::query()->whereKey($challenge->attempt_id)->first()
            : null;

        if (! $challenge instanceof AuthChallenge || ! $attempt instanceof AuthAttempt) {
            $this->terminalize($opaqueId, OtpOutboxFailureReason::TargetUnavailable);

            return;
        }

        $channel = match ($challenge->factor_type) {
            'email_otp' => 'email',
            'sms_otp' => 'sms',
            default => null,
        };

        if ($channel === null) {
            $this->terminalize($opaqueId, OtpOutboxFailureReason::TargetUnavailable);

            return;
        }

        $country = null;

        if ($channel === 'sms') {
            try {
                $normalized = $this->normalizer->normalize($identifier->value);
            } catch (\InvalidArgumentException) {
                $this->terminalize($opaqueId, OtpOutboxFailureReason::LegacyUnparseable);

                return;
            }

            $country = $normalized->country;
            $identifier->value = $normalized->e164;
        }

        $decision = $this->reserve(
            new DeliveryEconomicsRequest(
                $challenge->factor_type,
                $channel,
                $attempt->tenant_id,
                $country,
                $this->cost($channel),
                false,
                $outbox->opaque_id,
            ),
        );

        if ($decision === DeliveryReservationDecision::CountryNotAllowed) {
            $this->terminalize($opaqueId, OtpOutboxFailureReason::CountryNotAllowed);

            return;
        }

        if ($decision === DeliveryReservationDecision::SpendCeiling) {
            $this->terminalize($opaqueId, OtpOutboxFailureReason::SpendCeiling);

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

    private function reserve(DeliveryEconomicsRequest $request): DeliveryReservationDecision
    {
        for ($attempt = 0; $attempt < 3; $attempt++) {
            $decision = $this->economics->reserve($request);

            if ($decision !== DeliveryReservationDecision::RetryableContention) {
                return $decision;
            }

            usleep(20_000);
        }

        throw new RetryableOtpDeliveryFailure(
            'Delivery economics remained contended; no provider call was attempted.',
        );
    }

    private function cost(string $channel): int
    {
        $cost = $this->costs[$channel] ?? null;

        if (! is_int($cost) || $cost < 1) {
            throw new \InvalidArgumentException(sprintf(
                'A positive delivery cost is required for the %s channel.',
                $channel,
            ));
        }

        return $cost;
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
