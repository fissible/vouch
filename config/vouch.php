<?php

declare(strict_types=1);

return [
    /*
     * The application's authenticatable model. Vouch's foreign keys target
     * whatever this resolves to, so a host with a non-standard user model does
     * not need to edit migrations.
     */
    'user_model' => env('VOUCH_USER_MODEL', 'App\\Models\\User'),

    'attempts' => [
        // How long an in-progress authentication attempt stays valid.
        'ttl_seconds' => (int) env('VOUCH_ATTEMPT_TTL', 600),
    ],

    'recovery_grace' => [
        /*
         * Absolute lifetime of a recovery-grace session, from creation.
         * Never extended by activity (design §2, Expiry).
         */
        'ttl_seconds' => (int) env('VOUCH_RECOVERY_GRACE_TTL', 900),
    ],

    'sessions' => [
        // How long revoked session rows are retained before the sweep deletes them.
        'revocation_retention_days' => (int) env('VOUCH_REVOCATION_RETENTION_DAYS', 30),
    ],
];
