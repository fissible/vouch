<?php

declare(strict_types=1);

namespace Fissible\Vouch\Recovery;

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Delivery\DeliveryEconomicsRequest;
use Fissible\Vouch\Delivery\DeliveryReservationDecision;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthRecoveryProofOutbox;
use Fissible\Vouch\Notifications\OtpOutboxFailureReason;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Notifications\PermanentOtpDeliveryFailure;
use Fissible\Vouch\Notifications\TransientOtpDeliveryFailure;
use Fissible\Vouch\Support\DatabaseTime;
use Throwable;

/** Delivery lifecycle for recovery proofs; mirrors verification without sharing rows. */
final readonly class RecoveryProofOutboxDelivery
{
    public function __construct(private OtpDelivery $delivery, private DeliveryEconomics $economics, private DatabaseTime $time, private int $emailCost) {}

    public function deliver(string $opaqueId): void { $this->execute($opaqueId); }

    public function execute(string $opaqueId): void
    {
        $outbox = AuthRecoveryProofOutbox::query()->where('opaque_id', $opaqueId)->where('status', OtpOutboxStatus::Pending->value)->first();
        if (! $outbox instanceof AuthRecoveryProofOutbox) return;
        if ($this->expired($outbox)) { $this->terminalize($opaqueId); return; }
        $payload = $outbox->payload;
        if ($payload === null || $payload['decoy']) { $outbox->delete(); return; }
        $target = $payload['target'] ?? null;
        if (! is_array($target)) { $this->terminalize($opaqueId, OtpOutboxFailureReason::TargetUnavailable); return; }
        if ($this->emailCost < 1) { $this->terminalize($opaqueId, OtpOutboxFailureReason::WorkerFailure); return; }
        $request = new DeliveryEconomicsRequest('recovery_proof', 'email', null, null, $this->emailCost, false, $opaqueId);
        $decision = $this->reserve($request);
        if ($decision === DeliveryReservationDecision::CountryNotAllowed) { $this->terminalize($opaqueId, OtpOutboxFailureReason::CountryNotAllowed); return; }
        if ($decision === DeliveryReservationDecision::SpendCeiling) { $this->terminalize($opaqueId, OtpOutboxFailureReason::SpendCeiling); return; }
        try {
            AuthRecoveryProofOutbox::query()->whereKey($outbox->id)->where('status', OtpOutboxStatus::Pending->value)->update(['provider_attempted_at' => $this->time->now()]);
            $this->delivery->deliver(new AuthIdentifier($target), $payload['code'], $outbox->expires_at->toDateTimeImmutable());
        } catch (PermanentOtpDeliveryFailure) {
            $this->economics->release($request); $this->terminalize($opaqueId, OtpOutboxFailureReason::ProviderRejected); return;
        } catch (Throwable) {
            if ($this->expired($outbox)) { $this->economics->release($request); $this->terminalize($opaqueId); return; }
            throw new TransientOtpDeliveryFailure('Recovery proof delivery failed transiently; the encrypted outbox row remains pending.');
        }
        AuthRecoveryProofOutbox::query()->where('opaque_id', $opaqueId)->where('status', OtpOutboxStatus::Pending->value)->update(['payload' => null, 'status' => OtpOutboxStatus::Delivered->value, 'delivered_at' => $this->time->now()]);
    }

    public function terminalize(string $opaqueId, OtpOutboxFailureReason $reason = OtpOutboxFailureReason::ExpiredUndelivered): void
    {
        AuthRecoveryProofOutbox::query()->where('opaque_id', $opaqueId)->where('status', OtpOutboxStatus::Pending->value)->update(['payload' => null, 'status' => OtpOutboxStatus::Undeliverable->value, 'undeliverable_at' => $this->time->now(), 'failure_reason' => $reason->value]);
    }

    private function expired(AuthRecoveryProofOutbox $outbox): bool { return AuthRecoveryProofOutbox::query()->whereKey($outbox->id)->where('expires_at', '<=', $this->time->now())->exists(); }

    private function reserve(DeliveryEconomicsRequest $request): DeliveryReservationDecision
    {
        for ($attempt = 0; $attempt < 3; $attempt++) { $decision = $this->economics->reserve($request); if ($decision !== DeliveryReservationDecision::RetryableContention) return $decision; usleep(20_000); }
        throw new TransientOtpDeliveryFailure('Delivery economics remained contended; no provider call was attempted.');
    }
}
