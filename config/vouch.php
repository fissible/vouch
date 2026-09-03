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

    'doctor' => [
        // Keyset scan size for the diagnostic projection-drift report.
        'drift_batch' => (int) env('VOUCH_DOCTOR_DRIFT_BATCH', 500),
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

    /*
     * Ability names to the minimum recorded assurance they require. Route
     * middleware reads the host's existing authorization declarations, so a
     * map entry need not be duplicated on every protected route.
     */
    'assurance_requirements' => [],

    /*
     * The host's complete, intentional ability vocabulary. Gate definitions
     * and package database permissions are not enumerable at boot, so only
     * this declaration can make typo refusal a reliable opt-in contract.
     */
    'declared_abilities' => [],

    /*
     * Refuse boot when the map names an ability outside declared_abilities.
     * Off by default: publishing an authentication package must not surprise
     * an otherwise working host; the report command remains available to fix it.
     */
    'assurance_strict' => (bool) env('VOUCH_ASSURANCE_STRICT', false),

    'token_gate' => [
        /*
         * The gate is installed into the host's web and api groups, while
         * pre-existing tokens deliberately receive no assurance backfill.
         * Observe lets an operator identify tokens to reissue before arming
         * enforcement, rather than breaking existing API consumers at install.
         */
        'mode' => env('VOUCH_TOKEN_GATE_MODE', 'observe'),
    ],

    /*
     * Deliberately explicit: autoload roots do not describe the whole issuance
     * surface, especially route closures. The audit reports every root it did
     * open and names paths it could not inspect rather than silently skipping.
     */
    'audit' => [
        'paths' => ['app', 'routes'],
        'allowlist' => [],
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

        // Recovery proof is a separate ceremony from identifier verification.
        'ttl_seconds' => (int) env('VOUCH_RECOVERY_TTL', 300),
        'require_second_factor' => (bool) env('VOUCH_RECOVERY_REQUIRE_SECOND_FACTOR', false),
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

        /*
         * OTP delivery is deliberately isolated from the authentication
         * request. The configured connection must be durable and asynchronous;
         * sync, null, deferred, and background execution are refused before an
         * issuance event is charged.
         */
        'queue_connection' => env('VOUCH_OTP_QUEUE_CONNECTION'),
        'queue' => env('VOUCH_OTP_QUEUE', 'vouch-otp'),
    ],

    'verification' => [
        // Identifier-control ceremonies deliberately have their own lifetime.
        'ttl_seconds' => (int) env('VOUCH_VERIFICATION_TTL', 300),
    ],

    'delivery' => [
        'economics' => [
            // Minor units. Hosts should replace these with provider pricing.
            'email_cost_minor' => (int) env('VOUCH_EMAIL_DELIVERY_COST_MINOR', 1),
            'sms_cost_minor' => (int) env('VOUCH_SMS_DELIVERY_COST_MINOR', 1),
        ],
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

        // CAPTCHA escalation is an explicit adoption choice, separate from
        // enabling shared throttling. When enabled, a real verifier is required
        // at boot before the shared-volume rung can be reached under load.
        'captcha' => [
            'enabled' => env('VOUCH_THROTTLE_CAPTCHA_ENABLED', false),
        ],
    ],
];
