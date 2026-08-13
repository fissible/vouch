<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\Mutations\DisableCredential;
use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Factors\UnknownFactor;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;

function satisfiedFactor(string $id = 'password'): SatisfiedFactor
{
    return new SatisfiedFactor(
        factorId: $id,
        credentialId: '17',
        kind: FactorKind::Knowledge,
        strength: FactorStrength::Knowledge,
        isMultiFactor: false,
        userVerified: false,
        phishingResistant: false,
        authenticatorId: null,
        satisfiedAt: new DateTimeImmutable('2026-08-13T10:00:00+00:00'),
    );
}

it('carries the satisfied factor and its mutations on success', function (): void {
    $result = FactorResult::satisfied(satisfiedFactor(), new DisableCredential(17));

    expect($result->isSatisfied())->toBeTrue()
        ->and($result->factor?->factorId)->toBe('password')
        ->and($result->mutations)->toHaveCount(1)
        ->and($result->failure)->toBeNull();
});

it('carries a truthful reason and no mutations on failure', function (): void {
    $result = FactorResult::failed(FactorFailure::Mismatch);

    expect($result->isSatisfied())->toBeFalse()
        ->and($result->failure)->toBe(FactorFailure::Mismatch)
        ->and($result->factor)->toBeNull()
        ->and($result->mutations)->toBe([]);
});

it('distinguishes a wrong code from a wrong request context', function (): void {
    /*
     * Deliberate extension to the spec's five-case list. A code submitted from
     * the wrong IP is a different fact from a wrong code, and drivers report
     * truthfully — deciding those are the same is a disclosure judgement, which
     * belongs to ErrorShaper and nowhere else.
     */
    expect(FactorFailure::BindingMismatch)->not->toBe(FactorFailure::Mismatch);
});

it('resolves a driver by its registry key', function (): void {
    $registry = new FactorRegistry();
    $registry->register(fakeFactor('totp'));

    expect($registry->get('totp')->id())->toBe('totp')
        ->and($registry->has('totp'))->toBeTrue()
        ->and($registry->has('passkey'))->toBeFalse();
});

it('refuses an unknown factor rather than returning null', function (): void {
    // Returning null would push the "is this a real factor?" decision to every
    // call site, and one of them will forget.
    (new FactorRegistry())->get('passkey');
})->throws(UnknownFactor::class);

it('refuses to register two drivers under one key', function (): void {
    // Silent replacement would let a host swap the recovery-code driver for a
    // permissive one by registering after vouch does.
    $registry = new FactorRegistry();
    $registry->register(fakeFactor('totp'));
    $registry->register(fakeFactor('totp'));
})->throws(LogicException::class);

function fakeFactor(string $id): Factor
{
    return new class($id) implements Factor
    {
        public function __construct(private readonly string $id) {}

        public function id(): string
        {
            return $this->id;
        }

        public function kind(): FactorKind
        {
            return FactorKind::Possession;
        }

        public function strength(): FactorStrength
        {
            return FactorStrength::Possession;
        }

        public function maxActiveCredentials(): int
        {
            return 1;
        }

        public function enroll(int $userId, array $data): \Fissible\Vouch\Factors\EnrollmentResult
        {
            return new \Fissible\Vouch\Factors\EnrollmentResult([]);
        }

        public function challenge(\Fissible\Vouch\Factors\ChallengeRequest $request): ?\Fissible\Vouch\Models\AuthChallenge
        {
            return null;
        }

        public function verify(\Fissible\Vouch\Factors\VerificationRequest $request): FactorResult
        {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        public function revoke(\Fissible\Vouch\Models\AuthCredential $credential): void {}
    };
}
