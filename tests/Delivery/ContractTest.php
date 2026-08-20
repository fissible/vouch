<?php

declare(strict_types=1);

use Fissible\Vouch\Delivery\CaptchaDecision;
use Fissible\Vouch\Delivery\CaptchaRequest;
use Fissible\Vouch\Delivery\DeliveryEconomicsDecision;
use Fissible\Vouch\Delivery\DeliveryEconomicsRequest;
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
