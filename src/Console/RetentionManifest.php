<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

/** Declares the retention owner or durable purpose of every Vouch table. */
final class RetentionManifest
{
    /** @return array<string, string> */
    public static function pruned(): array
    {
        return [
            'auth_attempts' => 'VouchPruneCommand deletes expired authentication attempts.',
            'auth_challenges' => 'Expired attempts cascade their associated challenges during pruning.',
            'auth_challenge_outbox' => 'VouchPruneCommand removes expired OTP delivery outbox rows.',
            'auth_delivery_spend_reservations' => 'VouchPruneCommand reclaims closed historical delivery reservations.',
            'auth_identifier_verification_outbox' => 'VouchPruneCommand classifies and deletes expired identifier-verification deliveries before parent pruning.',
            'auth_recovery_proof_outbox' => 'VouchPruneCommand classifies and deletes expired recovery-proof deliveries before parent pruning.',
            'auth_identifier_verifications' => 'VouchPruneCommand deletes expired verification ceremonies; verified bindings remain on identifiers.',
            'auth_recovery_proofs' => 'VouchPruneCommand deletes expired recovery proofs; recovery grace remains on sessions.',
            'auth_link_requests' => 'VouchPruneCommand deletes expired link requests; completed ownership remains on federated identities.',
            'auth_sessions' => 'VouchPruneCommand removes revoked sessions after configured retention.',
            'auth_throttle_counters' => 'VouchPruneCommand removes counters beyond throttle retention.',
            'auth_throttle_locks' => 'VouchPruneCommand removes expired throttle lock state.',
            'auth_throttle_tuples' => 'VouchPruneCommand removes expired tuple replay markers.',
            'auth_token_assurances' => 'TokenAssuranceSweep deletes records only after issuer-confirmed absence.',
            'auth_token_credentials' => 'TokenAssuranceSweep deletes mappings with their assurance record.',
        ];
    }

    /** @return array<string, string> */
    public static function retained(): array
    {
        return [
            'auth_connections' => 'Connection definitions are durable account configuration, not ephemeral security state.',
            'auth_credentials' => 'Credential records remain authoritative until an explicit credential lifecycle action.',
            'auth_delivery_spend' => 'Global and tenant quota rows are durable accounting state, reset in place at each daily rollover.',
            'auth_enrollment_locks' => 'Permanent mutex anchors must survive so concurrent enrollment remains serialized.',
            'auth_federated_identities' => 'Federated identity bindings are durable login ownership records.',
            'auth_identifiers' => 'Identifier records are durable user identity configuration.',
            'auth_policies' => 'Authentication policy rows are durable host configuration.',
            'auth_proof_issuance_locks' => '#46: a fixed set of permanent bucket mutex anchors preserves issuance serialization after proofs are deleted; the migration seeds every row, so capacity never grows with requests and no identifiers are retained -- there is nothing to reclaim.',
            'auth_subject_locks' => '#17: permanent host-controlled subject mutex anchors preserve serialization after sessions are deleted; capacity grows with distinct token-issuing subjects.',
        ];
    }

    /** @return array<string, string> */
    public static function unreclaimed(): array
    {
        return [
            'auth_throttle_ip_windows' => '#16: permanent committed-row mutex anchors need a capacity decision for growth with distinct client IPs, not a prune.',
        ];
    }
}
