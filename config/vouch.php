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

    'challenges' => [
        /*
         * Factor types whose challenges MUST name the credential they were
         * delivered against. Configured rather than hardcoded so 2.2b can add
         * passkey without editing a model.
         *
         * Password and TOTP are absent deliberately: they issue no challenge and
         * have no delivery target, so requiring one would be a lie.
         */
        'require_credential' => ['email_otp', 'sms_otp'],
    ],

    'enrollment' => [
        /*
         * How long a contended enrollment waits for the (user_id, type) lock
         * before refusing. Bounded on purpose: the engine defaults are wildly
         * inconsistent — MySQL waits 50s, Postgres waits forever, SQLite fails
         * immediately — and an unbounded wait hangs a request thread.
         */
        'lock_wait_seconds' => (int) env('VOUCH_ENROLLMENT_LOCK_WAIT', 5),
    ],

    'recovery' => [
        // Regeneration replaces the whole set, so this is the size of a set.
        'count' => (int) env('VOUCH_RECOVERY_CODE_COUNT', 10),

        /*
         * Characters per code, drawn from a 32-symbol alphabet, so 10 characters
         * is 50 bits of entropy. Codes are generated with random_int(), a CSPRNG;
         * rand() and mt_rand() are predictable from observed output and must
         * never appear on this path.
         */
        'length' => (int) env('VOUCH_RECOVERY_CODE_LENGTH', 10),
    ],

    'totp' => [
        // Shown in the authenticator app next to the account label.
        'issuer' => env('VOUCH_TOTP_ISSUER', 'Vouch'),

        // RFC 6238 defaults. Changing period or digits invalidates enrolled secrets.
        'period' => (int) env('VOUCH_TOTP_PERIOD', 30),
        'digits' => (int) env('VOUCH_TOTP_DIGITS', 6),

        /*
         * Accepted timesteps either side of the current one, for clock drift.
         * 1 means three candidate steps in total. Expressed in STEPS rather than
         * seconds because the replay guard records a step: a seconds-based
         * leeway cannot tell you which step was accepted, and a guard that
         * cannot name the step it consumed permits the replay it appears to
         * prevent (RFC 6238 §5.2).
         */
        'window' => (int) env('VOUCH_TOTP_WINDOW', 1),
    ],

    'otp' => [
        /*
         * Digits per code. Generated with random_int(), a CSPRNG — rand() and
         * mt_rand() are predictable from observed output and must never appear
         * on this path.
         */
        'length' => (int) env('VOUCH_OTP_LENGTH', 6),

        // Short by design: a six-digit code is only 20 bits.
        'ttl_seconds' => (int) env('VOUCH_OTP_TTL', 120),
    ],
];
