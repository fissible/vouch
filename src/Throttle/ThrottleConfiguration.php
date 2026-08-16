<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

use InvalidArgumentException;

/**
 * Validated global authentication-throttle configuration.
 *
 * Login and recovery deliberately share one bounded-backoff schedule. Only the
 * login identifier path may additionally use lockAfter/lockDuration; recovery
 * consumes the schedule without acquiring lock authority.
 */
final readonly class ThrottleConfiguration
{
    public const int MAX_LOCK_DURATION_SECONDS = 3600;

    private const string PREFIX = 'vouch.throttle.';

    private function __construct(
        public int $windowSeconds,
        public int $retentionSeconds,
        public int $backoffAfter,
        public int $lockAfter,
        public int $backoffBase,
        public int $initialBackoffSeconds,
        public int $backoffCapSeconds,
        public int $lockDurationSeconds,
        public int $challengeAttempts,
        public int $issuancesPerIdentifier,
        public string $ipMode,
        public int $ipv6ObserveAt,
        public int $ipv4ObserveAt,
        public ?int $ipv6EnforceAt,
        public ?int $ipv4EnforceAt,
        public ?int $ipBackoffSeconds,
        public string $tenantMode,
        public ?int $tenantEnforceAt,
        public ?int $tenantBackoffSeconds,
        public string $globalMode,
        public ?int $globalEnforceAt,
        public ?int $globalBackoffSeconds,
    ) {}

    /**
     * @param mixed $value
     * @param mixed $otpDigits
     * @param mixed $totpDigits
     * @param mixed $totpWindow
     */
    public static function from($value, $otpDigits, $totpDigits, $totpWindow): self
    {
        if (! is_array($value)) {
            throw new InvalidArgumentException('Configuration "vouch.throttle" must be an array.');
        }

        /** @var array<array-key, mixed> $value */
        $windowSeconds = self::positive($value, 'window_seconds');
        $retentionSeconds = self::positive($value, 'retention_seconds');
        $backoffAfter = self::positive($value, 'identifier.backoff_after');
        $lockAfter = self::positive($value, 'identifier.lock_after');
        $backoffBase = self::positive($value, 'identifier.backoff_base');
        $initialBackoffSeconds = self::positive($value, 'identifier.initial_backoff_seconds');
        $backoffCapSeconds = self::positive($value, 'identifier.backoff_cap_seconds');
        $lockDurationSeconds = self::positive($value, 'identifier.lock_duration_seconds');
        $challengeAttempts = self::positive($value, 'challenge.attempts');
        $issuancesPerIdentifier = self::positive($value, 'challenge.issuances_per_identifier');
        $otpDigits = self::positiveValue($otpDigits, 'vouch.otp.length');
        $totpDigits = self::positiveValue($totpDigits, 'vouch.totp.digits');
        $totpWindow = self::nonNegativeValue($totpWindow, 'vouch.totp.window');

        $ipMode = self::mode($value, 'ip.mode');
        $ipv6ObserveAt = self::positive($value, 'ip.ipv6_observe_at');
        $ipv4ObserveAt = self::positive($value, 'ip.ipv4_observe_at');
        $ipv6EnforceAt = self::nullablePositive($value, 'ip.ipv6_enforce_at');
        $ipv4EnforceAt = self::nullablePositive($value, 'ip.ipv4_enforce_at');
        $ipBackoffSeconds = self::nullablePositive($value, 'ip.backoff_seconds');

        $tenantMode = self::mode($value, 'tenant.mode');
        $tenantEnforceAt = self::nullablePositive($value, 'tenant.enforce_at');
        $tenantBackoffSeconds = self::nullablePositive($value, 'tenant.backoff_seconds');

        $globalMode = self::mode($value, 'global.mode');
        $globalEnforceAt = self::nullablePositive($value, 'global.enforce_at');
        $globalBackoffSeconds = self::nullablePositive($value, 'global.backoff_seconds');

        self::require($backoffAfter < $lockAfter,
            'Configuration "vouch.throttle.identifier.backoff_after" must be less than '
            . '"vouch.throttle.identifier.lock_after".');
        self::require($backoffBase >= 2,
            'Configuration "vouch.throttle.identifier.backoff_base" must be at least 2.');
        self::require($backoffCapSeconds <= $windowSeconds,
            'Configuration "vouch.throttle.identifier.backoff_cap_seconds" must be less than '
            . 'or equal to "vouch.throttle.window_seconds".');
        self::require($lockDurationSeconds <= self::MAX_LOCK_DURATION_SECONDS,
            'Configuration "vouch.throttle.identifier.lock_duration_seconds" must not exceed '
            . '3600 seconds. Longer locks require Phase 2.4 audited administrative unlock.');
        self::require($retentionSeconds >= $windowSeconds + self::MAX_LOCK_DURATION_SECONDS,
            'Configuration "vouch.throttle.retention_seconds" must be at least '
            . '"vouch.throttle.window_seconds" + 3600 so pruning cannot delete live lock state.');
        self::require($ipv4ObserveAt > $ipv6ObserveAt,
            'Configuration "vouch.throttle.ip.ipv4_observe_at" must be greater than '
            . '"vouch.throttle.ip.ipv6_observe_at" because IPv4 buckets may contain CGNAT populations.');
        self::guessBudgets(
            $challengeAttempts,
            $issuancesPerIdentifier,
            $otpDigits,
            $lockAfter,
            $totpDigits,
            $totpWindow,
        );

        self::sharedIp($ipMode, $ipv6EnforceAt, $ipv4EnforceAt, $ipBackoffSeconds, $backoffCapSeconds);
        self::sharedOne('tenant', $tenantMode, $tenantEnforceAt, $tenantBackoffSeconds, $backoffCapSeconds);
        self::sharedOne('global', $globalMode, $globalEnforceAt, $globalBackoffSeconds, $backoffCapSeconds);

        return new self(
            $windowSeconds,
            $retentionSeconds,
            $backoffAfter,
            $lockAfter,
            $backoffBase,
            $initialBackoffSeconds,
            $backoffCapSeconds,
            $lockDurationSeconds,
            $challengeAttempts,
            $issuancesPerIdentifier,
            $ipMode,
            $ipv6ObserveAt,
            $ipv4ObserveAt,
            $ipv6EnforceAt,
            $ipv4EnforceAt,
            $ipBackoffSeconds,
            $tenantMode,
            $tenantEnforceAt,
            $tenantBackoffSeconds,
            $globalMode,
            $globalEnforceAt,
            $globalBackoffSeconds,
        );
    }

    /** @param array<array-key, mixed> $config */
    private static function positive(array $config, string $path): int
    {
        return self::positiveValue(self::read($config, $path), self::PREFIX . $path);
    }

    private static function positiveValue(mixed $value, string $key): int
    {
        if (is_int($value) && $value > 0) {
            return $value;
        }

        if (is_string($value) && preg_match('/^[1-9][0-9]*$/D', $value) === 1) {
            $integer = filter_var($value, FILTER_VALIDATE_INT);

            if (is_int($integer) && $integer > 0) {
                return $integer;
            }
        }

        throw new InvalidArgumentException(sprintf(
            'Configuration "%s" must be a positive integer; got %s.',
            $key,
            self::describe($value),
        ));
    }

    private static function nonNegativeValue(mixed $value, string $key): int
    {
        if (is_int($value) && $value >= 0) {
            return $value;
        }

        if (is_string($value) && preg_match('/^(?:0|[1-9][0-9]*)$/D', $value) === 1) {
            $integer = filter_var($value, FILTER_VALIDATE_INT);

            if (is_int($integer) && $integer >= 0) {
                return $integer;
            }
        }

        throw new InvalidArgumentException(sprintf(
            'Configuration "%s" must be a non-negative integer; got %s.',
            $key,
            self::describe($value),
        ));
    }

    /** @param array<array-key, mixed> $config */
    private static function nullablePositive(array $config, string $path): ?int
    {
        $value = self::read($config, $path);

        return $value === null ? null : self::positive($config, $path);
    }

    /** @param array<array-key, mixed> $config */
    private static function mode(array $config, string $path): string
    {
        $value = self::read($config, $path);

        if ($value === 'observe' || $value === 'enforce') {
            return $value;
        }

        throw new InvalidArgumentException(sprintf(
            'Configuration "%s%s" must be exactly "observe" or "enforce"; got %s.',
            self::PREFIX,
            $path,
            self::describe($value),
        ));
    }

    /** @param array<array-key, mixed> $config */
    private static function read(array $config, string $path): mixed
    {
        $cursor = $config;

        $segments = explode('.', $path);
        $last = count($segments) - 1;

        foreach ($segments as $index => $segment) {
            if (! array_key_exists($segment, $cursor)) {
                throw new InvalidArgumentException(sprintf(
                    'Missing required configuration key "%s%s"; Vouch has no inline fallback for it.',
                    self::PREFIX,
                    $path,
                ));
            }

            $value = $cursor[$segment];

            if ($index === $last) {
                return $value;
            }

            if (! is_array($value)) {
                throw new InvalidArgumentException(sprintf(
                    'Configuration "%s%s" must be nested under an array.',
                    self::PREFIX,
                    $path,
                ));
            }

            /** @var array<array-key, mixed> $value */
            $cursor = $value;
        }

        throw new InvalidArgumentException('Unreachable configuration path.');
    }

    private static function sharedIp(
        string $mode,
        ?int $ipv6Threshold,
        ?int $ipv4Threshold,
        ?int $backoffSeconds,
        int $maximumBackoffSeconds,
    ): void {
        if ($mode === 'observe') {
            self::require(
                $ipv6Threshold === null && $ipv4Threshold === null && $backoffSeconds === null,
                'Configuration "vouch.throttle.ip" is in observe mode; enforcement thresholds '
                . 'and backoff must remain null until mode is explicitly "enforce".',
            );

            return;
        }

        self::require($ipv6Threshold !== null,
            'Configuration "vouch.throttle.ip.ipv6_enforce_at" is required when IP mode is "enforce".');
        self::require($ipv4Threshold !== null,
            'Configuration "vouch.throttle.ip.ipv4_enforce_at" is required when IP mode is "enforce".');
        self::require($backoffSeconds !== null,
            'Configuration "vouch.throttle.ip.backoff_seconds" is required when IP mode is "enforce".');

        if ($ipv6Threshold !== null && $ipv4Threshold !== null) {
            self::require($ipv4Threshold > $ipv6Threshold,
                'Configuration "vouch.throttle.ip.ipv4_enforce_at" must be greater than '
                . '"vouch.throttle.ip.ipv6_enforce_at".');
        }

        if ($backoffSeconds !== null) {
            self::require($backoffSeconds <= $maximumBackoffSeconds,
                'Configuration "vouch.throttle.ip.backoff_seconds" must not exceed the '
                . 'identifier backoff cap; shared-bucket delays stay seconds-scale.');
        }
    }

    private static function guessBudgets(
        int $challengeAttempts,
        int $issuancesPerIdentifier,
        int $otpDigits,
        int $lockAfter,
        int $totpDigits,
        int $totpWindow,
    ): void {
        $target = 0.0001;
        $otpProbability = (2.0 * $challengeAttempts * $issuancesPerIdentifier)
            / (10.0 ** $otpDigits);

        self::require($otpProbability <= $target,
            'Configuration "vouch.throttle.challenge.attempts" × '
            . '"vouch.throttle.challenge.issuances_per_identifier" exceeds the 10^-4 '
            . 'fixed-boundary online-guess target for "vouch.otp.length".');

        $validTotpCodes = ($totpWindow * 2) + 1;
        $totpProbability = (2.0 * $lockAfter * $validTotpCodes)
            / (10.0 ** $totpDigits);

        self::require($totpProbability <= $target,
            'Configuration "vouch.throttle.identifier.lock_after" exceeds the 10^-4 '
            . 'fixed-boundary online-guess target for "vouch.totp.digits" and '
            . '"vouch.totp.window".');
    }

    private static function sharedOne(
        string $dimension,
        string $mode,
        ?int $threshold,
        ?int $backoffSeconds,
        int $maximumBackoffSeconds,
    ): void {
        if ($mode === 'observe') {
            self::require(
                $threshold === null && $backoffSeconds === null,
                sprintf(
                    'Configuration "vouch.throttle.%s" is in observe mode; enforcement threshold '
                    . 'and backoff must remain null until mode is explicitly "enforce".',
                    $dimension,
                ),
            );

            return;
        }

        self::require($threshold !== null, sprintf(
            'Configuration "vouch.throttle.%s.enforce_at" is required when %s mode is "enforce".',
            $dimension,
            $dimension,
        ));
        self::require($backoffSeconds !== null, sprintf(
            'Configuration "vouch.throttle.%s.backoff_seconds" is required when %s mode is "enforce".',
            $dimension,
            $dimension,
        ));

        if ($backoffSeconds !== null) {
            self::require($backoffSeconds <= $maximumBackoffSeconds, sprintf(
                'Configuration "vouch.throttle.%s.backoff_seconds" must not exceed the identifier '
                . 'backoff cap; shared-bucket delays stay seconds-scale.',
                $dimension,
            ));
        }
    }

    private static function require(bool $condition, string $message): void
    {
        if (! $condition) {
            throw new InvalidArgumentException($message);
        }
    }

    private static function describe(mixed $value): string
    {
        return match (true) {
            $value === '' => 'an empty string',
            is_string($value) => 'string "' . $value . '"',
            is_int($value) => (string) $value,
            $value === null => 'null',
            default => get_debug_type($value),
        };
    }
}
