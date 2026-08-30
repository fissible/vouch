<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

use Fissible\Vouch\Assurance\AssuranceEvidence;
use Fissible\Vouch\Assurance\EvidenceRead;
use Fissible\Vouch\Assurance\AssuranceReason;
use Fissible\Vouch\Assurance\MalformedEvidence;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Tokens\SubjectKey;
use Illuminate\Database\Eloquent\Model;

final class SessionEvidence
{
    public static function for(?AuthSession $session): ?AssuranceEvidence
    {
        return self::read($session)->evidence;
    }

    public static function read(?AuthSession $session): EvidenceRead
    {
        if (! $session instanceof AuthSession) {
            return new EvidenceRead(null, AssuranceReason::NoEvidence);
        }
        // This order is the refusal contract: later checks must not relabel a
        // revoked session as grace, legacy, malformed, or subject-mismatched.
        if ($session->revoked_at !== null) {
            return new EvidenceRead(null, AssuranceReason::SessionRevoked);
        }
        if ($session->isRecoveryGrace()) {
            return new EvidenceRead(null, AssuranceReason::RecoveryGrace);
        }
        if ($session->assurance_proof === null) {
            return new EvidenceRead(null, AssuranceReason::LegacyNoProof);
        }
        // Misconfiguration is an operational failure, not malformed tenant
        // data. Resolve it before parsing so ProofMalformed stays truthful.
        $model = self::configuredUserModel();

        try {
            $evidence = AssuranceEvidence::fromArray($session->assurance_proof);
            $expected = SubjectKey::of((new $model)->getMorphClass(), $session->user_id);
            if (! $evidence->subject->equals($expected)) {
                return new EvidenceRead(null, AssuranceReason::SubjectMismatch);
            }
        } catch (MalformedEvidence) {
            return new EvidenceRead(null, AssuranceReason::ProofMalformed);
        }

        return new EvidenceRead($evidence, AssuranceReason::Sufficient);
    }

    /** @return class-string<Model> */
    private static function configuredUserModel(): string
    {
        $model = config('auth.providers.users.model');

        if (! is_string($model) || ! is_subclass_of($model, Model::class)) {
            throw new \RuntimeException('auth.providers.users.model is not an Eloquent model.');
        }

        return $model;
    }
}
