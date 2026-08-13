<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor;
use Fissible\Vouch\Factors\Drivers\SmsOtpFactor;
use Fissible\Vouch\Factors\Drivers\TotpFactor;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Notifications\UnconfiguredOtpDelivery;
use Fissible\Vouch\Support\SystemClock;
use Psr\Clock\ClockInterface;

it('registers all five drivers under their credential type keys', function (): void {
    // The keys must match auth_credentials.type exactly. A mismatch would mean a
    // stored credential no driver can verify -- a lockout, discovered in 2.3.
    $registry = app(FactorRegistry::class);

    expect(array_map(fn ($f): string => $f->id(), $registry->all()))
        ->toEqualCanonicalizing(['password', 'totp', 'email_otp', 'sms_otp', 'recovery_code']);
});

it('resolves each driver to its expected class', function (): void {
    $registry = app(FactorRegistry::class);

    expect($registry->get('password'))->toBeInstanceOf(PasswordFactor::class)
        ->and($registry->get('totp'))->toBeInstanceOf(TotpFactor::class)
        ->and($registry->get('email_otp'))->toBeInstanceOf(EmailOtpFactor::class)
        ->and($registry->get('sms_otp'))->toBeInstanceOf(SmsOtpFactor::class)
        ->and($registry->get('recovery_code'))->toBeInstanceOf(RecoveryCodeFactor::class);
});

it('does not register passkey, which is 2.2b', function (): void {
    expect(app(FactorRegistry::class)->has('passkey'))->toBeFalse();
});

it('returns one shared registry rather than rebuilding it', function (): void {
    expect(app(FactorRegistry::class))->toBe(app(FactorRegistry::class));
});

it('binds a psr clock', function (): void {
    expect(app(ClockInterface::class))->toBeInstanceOf(SystemClock::class);
});

it('binds an enrollment guard', function (): void {
    expect(app(EnrollmentGuard::class))->toBeInstanceOf(EnrollmentGuard::class);
});

it('defaults otp delivery to something that throws rather than something silent', function (): void {
    // A no-op default would make "OTP is not configured" indistinguishable from
    // "the code never arrived", and only in production.
    expect(app(OtpDelivery::class))->toBeInstanceOf(UnconfiguredOtpDelivery::class);
});

it('carries the cardinality rule each driver declares in the spec', function (): void {
    $registry = app(FactorRegistry::class);

    expect($registry->get('password')->maxActiveCredentials())->toBe(1)
        ->and($registry->get('totp')->maxActiveCredentials())->toBe(1)
        ->and($registry->get('recovery_code')->maxActiveCredentials())->toBe(10)
        ->and($registry->get('email_otp')->maxActiveCredentials())->toBeNull()
        ->and($registry->get('sms_otp')->maxActiveCredentials())->toBeNull();
});

it('declares the strength each driver is entitled to and no more', function (): void {
    /*
     * Pins each driver's declared strength exactly. Strength is what the kernel
     * reads: Recovery is filtered out of satisfiability entirely, and a driver
     * that quietly promoted itself to PossessionStrong would satisfy a
     * high-assurance policy it has no business satisfying. None of the five is
     * entitled to that -- it is reserved for the phishing-resistant passkey
     * arriving in 2.2b.
     */
    $registry = app(FactorRegistry::class);

    expect($registry->get('password')->strength())->toBe(FactorStrength::Knowledge)
        ->and($registry->get('totp')->strength())->toBe(FactorStrength::Possession)
        ->and($registry->get('email_otp')->strength())->toBe(FactorStrength::PossessionWeak)
        ->and($registry->get('sms_otp')->strength())->toBe(FactorStrength::PossessionWeak)
        ->and($registry->get('recovery_code')->strength())->toBe(FactorStrength::Recovery);
});

it('a misconfigured totp issuer makes the whole registry unresolvable', function (): void {
    /*
     * Accepted behaviour, not an oversight. The registry is registered as one
     * eager closure that resolves all five drivers so write-once registration
     * and all() can be trusted -- so a blank VOUCH_TOTP_ISSUER takes password,
     * recovery-code, and the OTP drivers down with TOTP, not just TOTP. A
     * silently defaulted issuer was considered and rejected: quietly masking
     * misconfiguration in a package that authenticates people is worse than a
     * loud failure that names the offending config key.
     */
    config()->set('vouch.totp.issuer', '');

    // The message is the whole justification for the blast radius: asserting the
    // class alone would let the config key drop out of the message unnoticed.
    expect(fn () => app(FactorRegistry::class))
        ->toThrow(InvalidArgumentException::class, 'vouch.totp.issuer');
});

it('refuses a zero otp length rather than delivering empty codes', function (): void {
    /*
     * `VOUCH_OTP_LENGTH=` — set but blank, which deploy tooling emits routinely —
     * is `(int) ''` and therefore 0. Unguarded, that generates '' as the code,
     * stores Hash::make('') on the challenge, and password_verify('', ...)
     * returns TRUE, so any submission of nothing satisfies a PossessionWeak
     * factor. Loud at boot is the only acceptable outcome.
     */
    config()->set('vouch.otp.length', 0);

    expect(fn () => app(FactorRegistry::class))
        ->toThrow(InvalidArgumentException::class, 'vouch.otp.length');
});

it('refuses a zero otp ttl rather than expiring every code on delivery', function (): void {
    config()->set('vouch.otp.ttl_seconds', 0);

    expect(fn () => app(FactorRegistry::class))
        ->toThrow(InvalidArgumentException::class, 'vouch.otp.ttl_seconds');
});

it('refuses a zero recovery code length rather than generating empty codes', function (): void {
    config()->set('vouch.recovery.length', 0);

    expect(fn () => app(FactorRegistry::class))
        ->toThrow(InvalidArgumentException::class, 'vouch.recovery.length');
});

it('refuses a zero recovery code count rather than enrolling an empty set', function (): void {
    config()->set('vouch.recovery.count', 0);

    expect(fn () => app(FactorRegistry::class))
        ->toThrow(InvalidArgumentException::class, 'vouch.recovery.count');
});
