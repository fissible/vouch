<?php

declare(strict_types=1);

use Fissible\Vouch\Delivery\CaptchaDecision;
use Fissible\Vouch\Delivery\CaptchaRequest;
use Fissible\Vouch\Delivery\DeliveryEconomicsDecision;
use Fissible\Vouch\Delivery\DeliveryEconomicsRequest;
use Fissible\Vouch\Delivery\SmsCountryNormalizer;
use Fissible\Vouch\Delivery\UnconfiguredCaptchaVerifier;
use Fissible\Vouch\Delivery\UnconfiguredDeliveryEconomics;

it('keeps delivery economics decisions explicit and decoy-safe', function (): void {
    expect(DeliveryEconomicsDecision::cases())->toEqual([
        DeliveryEconomicsDecision::Permitted,
        DeliveryEconomicsDecision::Refused,
    ]);

    expect(new DeliveryEconomicsRequest(
        factorId: 'sms_otp',
        channel: 'sms',
        tenantId: null,
        country: null,
        costMinor: 4,
        decoy: true,
    )->decoy)->toBeTrue();

    expect(fn () => new DeliveryEconomicsRequest(
        factorId: 'sms_otp',
        channel: 'sms',
        tenantId: null,
        country: 'US',
        costMinor: 4,
        decoy: true,
    ))->toThrow('decoy delivery cannot carry a country target');
});

it('fails closed when delivery economics is unconfigured', function (): void {
    $request = new DeliveryEconomicsRequest('email_otp', 'email', null, null, 1, true);
    $economics = new UnconfiguredDeliveryEconomics();

    expect(fn () => $economics->preflight($request))
        ->toThrow('No OTP delivery economics is configured');
    expect(fn () => $economics->reserve($request))
        ->toThrow('No OTP delivery economics is configured');
});

it('keeps CAPTCHA verification provider-independent and fail-closed', function (): void {
    expect(CaptchaDecision::cases())->toEqual([
        CaptchaDecision::Passed,
        CaptchaDecision::Failed,
    ]);

    expect(fn () => (new UnconfiguredCaptchaVerifier())->verify(new CaptchaRequest('token', null)))
        ->toThrow('No CAPTCHA verifier is configured');
});

it('canonicalizes valid international SMS numbers and refuses ambiguous input', function (): void {
    $normalizer = SmsCountryNormalizer::defaults();

    expect($normalizer->normalize('+1 415 555 2671')->e164)->toBe('+14155552671')
        ->and($normalizer->normalize('+1 415 555 2671')->country)->toBe('US');

    expect(fn () => $normalizer->normalize('4155552671'))
        ->toThrow('not a parseable international phone number');
    expect(fn () => $normalizer->normalize('+1415'))
        ->toThrow('not a valid international phone number');
});
