<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Delivery\DeliveryChannel;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Delivery\DeliveryEconomicsDecision;
use Fissible\Vouch\Delivery\DeliveryEconomicsRequest;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Notifications\OtpChallengeOutbox;
use Fissible\Vouch\Notifications\UnconfiguredOtpDelivery;
use Fissible\Vouch\Throttle\IssuancePermission;
use Fissible\Vouch\Throttle\ThrottleKey;
use InvalidArgumentException;
use RuntimeException;

/** Sole production owner of factor challenge issuance. */
final readonly class ChallengeIssuer
{
    /** @param list<string> $challengeFactors */
    public function __construct(
        private AuthThrottleStore $throttles,
        private ThrottleKey $keys,
        private FactorRegistry $factors,
        private DeliveryEconomics $economics,
        private OtpDelivery $delivery,
        private OtpChallengeOutbox $outbox,
        private array $challengeFactors,
    ) {}

    public function supports(string $factorId): bool
    {
        return in_array($factorId, $this->challengeFactors, true)
            && $this->factors->has($factorId);
    }

    /** Charge before any target, user, or credential resolution. */
    public function permit(ChallengeIssuanceIntent $intent): ChallengeIssuanceTicket
    {
        if (! $this->supports($intent->factorId)) {
            throw new InvalidArgumentException(sprintf(
                'Factor "%s" is not a challenge-delivery factor.',
                $intent->factorId,
            ));
        }

        if ($this->delivery instanceof UnconfiguredOtpDelivery) {
            throw UnconfiguredOtpDelivery::exception();
        }

        // Queue posture is checked before the counter, for every identifier.
        $this->outbox->assertReady();

        return new ChallengeIssuanceTicket(
            $intent,
            $this->throttles->permitIssuance(
                $this->keys->issuance($intent->submittedIdentifier, $intent->tenantId),
            ),
        );
    }

    /** Resolve the server-owned target or decoy only after permission exists. */
    public function complete(
        ChallengeIssuanceTicket $ticket,
        AuthAttempt $attempt,
    ): ?AuthChallenge {
        if ($ticket->permission === IssuancePermission::Refused) {
            return null;
        }

        if ($ticket->intent->attemptId !== $attempt->id) {
            throw new RuntimeException('The issuance ticket belongs to another attempt.');
        }

        // Run the same credential query for known and unknown identifiers.
        // Laravel compiles a null user id to IS NULL; the schema's NOT NULL
        // premise makes that the durable decoy result without skipping work.
        $candidates = AuthCredential::query()
            ->where('user_id', $attempt->user_id)
            ->where('type', $ticket->intent->factorId)
            ->whereNull('disabled_at')
            ->get();

        $credential = $candidates->count() === 1 ? $candidates->first() : null;

        $economics = $this->economics->preflight(new DeliveryEconomicsRequest(
            factorId: $ticket->intent->factorId,
            channel: $this->channel($ticket->intent->factorId),
            tenantId: $ticket->intent->tenantId,
            country: null,
            // Request preflight never charges; the worker's target-bearing
            // reservation will carry the configured delivery cost.
            costMinor: 0,
            decoy: ! $credential instanceof AuthCredential,
        ));

        if ($economics === DeliveryEconomicsDecision::Refused) {
            return null;
        }

        // The delivery-economics boundary belongs exactly here: after volume
        // permission and target resolution, before the factor call.
        return $this->issueAfterDeliveryEconomicsBoundary(
            $ticket,
            $attempt,
            $credential,
        );
    }

    private function issueAfterDeliveryEconomicsBoundary(
        ChallengeIssuanceTicket $ticket,
        AuthAttempt $attempt,
        ?AuthCredential $credential,
    ): ?AuthChallenge {
        return $this->factors->get($ticket->intent->factorId)->challenge(new ChallengeRequest(
            attempt: $attempt,
            credential: $credential,
            clientIp: $ticket->intent->clientIp,
            clientUserAgent: $ticket->intent->clientUserAgent,
            decoy: ! $credential instanceof AuthCredential,
            reusePending: $ticket->intent->action === 'resend',
        ));
    }

    private function channel(string $factorId): string
    {
        return DeliveryChannel::fromFactor($factorId);
    }
}
