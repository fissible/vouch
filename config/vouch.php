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

    'step_up' => [
        /*
         * REQUIRED before any route uses vouch.assurance. No default: 2.3 ships
         * no routeable step-up page, and a wrong guess sends browsers to a
         * POST-only endpoint. Phase 3's adapters provide this page.
         */
        'presentation_url' => env('VOUCH_STEP_UP_URL'),

        // Where a completed step-up returns when no intended target survived.
        'default_return' => env('VOUCH_STEP_UP_DEFAULT_RETURN', '/'),
    ],

    'routes' => [
        'prefix' => env('VOUCH_ROUTE_PREFIX', 'vouch'),

        /*
         * Inside `web` by default so session and CSRF protection apply. This is
         * a convenience default, NOT the guarantee — AuthFlow independently
         * requires a bound context on creation and every advance, because
         * middleware configuration can change after boot.
         */
        'middleware' => ['web'],
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

    /*
     * Authentication throttling. These values deliberately are NOT cast here:
     * `(int) env(...)` turns a set-but-blank variable into zero. The provider
     * resolves ThrottleConfiguration during boot, where numeric strings become
     * integers and blank, missing, or relationally-invalid values fail loudly.
     */
    'throttle' => [
        'window_seconds' => env('VOUCH_THROTTLE_WINDOW_SECONDS', 900),
        'retention_seconds' => env('VOUCH_THROTTLE_RETENTION_SECONDS', 86400),

        'identifier' => [
            'backoff_after' => env('VOUCH_THROTTLE_BACKOFF_AFTER', 5),
            'lock_after' => env('VOUCH_THROTTLE_LOCK_AFTER', 10),
            'backoff_base' => env('VOUCH_THROTTLE_BACKOFF_BASE', 2),
            'initial_backoff_seconds' => env('VOUCH_THROTTLE_INITIAL_BACKOFF_SECONDS', 1),
            'backoff_cap_seconds' => env('VOUCH_THROTTLE_BACKOFF_CAP_SECONDS', 60),
            'lock_duration_seconds' => env('VOUCH_THROTTLE_LOCK_DURATION_SECONDS', 900),
        ],

        'challenge' => [
            'attempts' => env('VOUCH_THROTTLE_CHALLENGE_ATTEMPTS', 5),
            'issuances_per_identifier' => env('VOUCH_THROTTLE_ISSUANCES_PER_IDENTIFIER', 5),
        ],

        /*
         * IP thresholds count distinct submitted identifiers per window, not
         * raw requests. Observe mode records aggregate distributions only.
         * Enforcement has no defaults: mode, both family thresholds, and a
         * seconds-scale backoff must be supplied together.
         */
        'ip' => [
            'mode' => env('VOUCH_THROTTLE_IP_MODE', 'observe'),
            'ipv6_observe_at' => env('VOUCH_THROTTLE_IPV6_OBSERVE_AT', 30),
            'ipv4_observe_at' => env('VOUCH_THROTTLE_IPV4_OBSERVE_AT', 300),
            'ipv6_enforce_at' => env('VOUCH_THROTTLE_IPV6_ENFORCE_AT'),
            'ipv4_enforce_at' => env('VOUCH_THROTTLE_IPV4_ENFORCE_AT'),
            'backoff_seconds' => env('VOUCH_THROTTLE_IP_BACKOFF_SECONDS'),
        ],

        /*
         * Tenant and global counters are observable but unarmed by default.
         * Their blast radius makes opt-in enforcement the only safe default.
         */
        'tenant' => [
            'mode' => env('VOUCH_THROTTLE_TENANT_MODE', 'observe'),
            'enforce_at' => env('VOUCH_THROTTLE_TENANT_ENFORCE_AT'),
            'backoff_seconds' => env('VOUCH_THROTTLE_TENANT_BACKOFF_SECONDS'),
        ],

        'global' => [
            'mode' => env('VOUCH_THROTTLE_GLOBAL_MODE', 'observe'),
            'enforce_at' => env('VOUCH_THROTTLE_GLOBAL_ENFORCE_AT'),
            'backoff_seconds' => env('VOUCH_THROTTLE_GLOBAL_BACKOFF_SECONDS'),
        ],
    ],
];
