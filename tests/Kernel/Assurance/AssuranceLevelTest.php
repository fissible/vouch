<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Assurance\AssuranceLevel;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Kernel\Assurance\NistAssuranceVocabulary;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Psr\Clock\ClockInterface;

function at(string $iso): DateTimeImmutable
{
    return new DateTimeImmutable($iso);
}

function frozenClock(string $iso): ClockInterface
{
    return new class(at($iso)) implements ClockInterface {
        public function __construct(private readonly DateTimeImmutable $now) {}

        public function now(): DateTimeImmutable
        {
            return $this->now;
        }
    };
}

function satisfied(
    string $credentialId,
    FactorStrength $strength,
    bool $phishingResistant,
    string $iso,
    bool $multiFactor = false,
): SatisfiedFactor {
    return new SatisfiedFactor(
        factorId: 'f',
        credentialId: $credentialId,
        kind: FactorKind::Possession,
        strength: $strength,
        isMultiFactor: $multiFactor,
        userVerified: $multiFactor,
        phishingResistant: $phishingResistant,
        authenticatorId: null,
        satisfiedAt: at($iso),
    );
}

it('counts distinct credentials, not satisfactions', function (): void {
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Knowledge, false, '2026-08-11T10:00:00+00:00'),
        satisfied('cred-1', FactorStrength::Knowledge, false, '2026-08-11T10:01:00+00:00'),
        satisfied('cred-2', FactorStrength::Possession, false, '2026-08-11T10:02:00+00:00'),
    ]);

    expect($facts->distinctCredentialCount)->toBe(2);
});

it('reports the strongest factor', function (): void {
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Knowledge, false, '2026-08-11T10:00:00+00:00'),
        satisfied('cred-2', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00'),
    ]);

    expect($facts->strongest)->toBe(FactorStrength::PossessionStrong);
});

it('is phishing resistant only when every factor is', function (): void {
    $mixed = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Knowledge, false, '2026-08-11T10:00:00+00:00'),
        satisfied('cred-2', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00'),
    ]);

    expect($mixed->allPhishingResistant)->toBeFalse();
});

it('takes recency from the oldest factor, not the newest', function (): void {
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Knowledge, false, '2026-08-11T08:00:00+00:00'),
        satisfied('cred-2', FactorStrength::Possession, false, '2026-08-11T10:00:00+00:00'),
    ]);

    expect($facts->weakestSatisfiedAt?->format('H:i'))->toBe('08:00');
});

it('keeps the first of two equal-instant factors as the oldest', function (): void {
    // Two factors satisfied at the same instant but in different timezones compare
    // equal (==) yet are not interchangeable: same instant, different rendering.
    // fromFactors() must retain the first of a tie, not the second, so
    // weakestSatisfiedAt's timezone is deterministic rather than an accident of
    // iteration order.
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Possession, false, '2026-08-11T10:00:00+00:00'),
        satisfied('cred-2', FactorStrength::Possession, false, '2026-08-11T12:00:00+02:00'),
    ]);

    expect($facts->weakestSatisfiedAt?->format('c'))->toBe('2026-08-11T10:00:00+00:00');
});

it('fails recency when the oldest factor is beyond max age', function (): void {
    $level = new AssuranceLevel('aal2', AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Possession, false, '2026-08-11T08:00:00+00:00'),
    ]));

    $withinTwoHours = $level->satisfiesRecency(
        new DateInterval('PT2H'),
        frozenClock('2026-08-11T11:00:00+00:00'),
    );

    expect($withinTwoHours)->toBeFalse();
});

it('passes recency inside max age', function (): void {
    $level = new AssuranceLevel('aal2', AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Possession, false, '2026-08-11T10:00:00+00:00'),
    ]));

    $withinTwoHours = $level->satisfiesRecency(
        new DateInterval('PT2H'),
        frozenClock('2026-08-11T11:00:00+00:00'),
    );

    expect($withinTwoHours)->toBeTrue();
});

it('names two distinct credentials aal2 under the NIST vocabulary', function (): void {
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Knowledge, false, '2026-08-11T10:00:00+00:00'),
        satisfied('cred-2', FactorStrength::Possession, false, '2026-08-11T10:00:00+00:00'),
    ]);

    expect((new NistAssuranceVocabulary())->name($facts))->toBe('aal2');
});

it('caps at aal2 for a phishing-resistant strong passkey', function (): void {
    // AAL3 additionally requires a non-exportable key in hardware. A syncable
    // passkey is phishing-resistant but not AAL3-eligible, and the kernel records
    // no hardware-binding evidence either way — so the default must never emit it.
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00', multiFactor: true),
    ]);

    expect((new NistAssuranceVocabulary())->name($facts))->toBe('aal2');
});

it('never emits aal3 across its whole decision-relevant facts space', function (): void {
    $vocabulary = new NistAssuranceVocabulary();

    // Exhaustive, not a sample: the vocabulary branches only on credential count
    // 0 / 1 / >=2, so counts 0..2 crossed with every strength and both booleans
    // covers every decision it can make. Sixty combinations.
    foreach ([0, 1, 2] as $credentialCount) {
        foreach (FactorStrength::cases() as $strongest) {
            foreach ([true, false] as $phishingResistant) {
                foreach ([true, false] as $multiFactor) {
                    $facts = new AssuranceFacts(
                        distinctCredentialCount: $credentialCount,
                        strongest: $strongest,
                        allPhishingResistant: $phishingResistant,
                        hasMultiFactorCredential: $multiFactor,
                        weakestSatisfiedAt: at('2026-08-11T10:00:00+00:00'),
                    );

                    expect($vocabulary->name($facts))->not->toBe('aal3');
                }
            }
        }
    }
});

it('lets an application supply a vocabulary that reads phishing resistance', function (): void {
    // Demonstrates the extension point, and is the reason AssuranceFacts exposes
    // allPhishingResistant even though the conservative default does not read it.
    $strict = new class implements AssuranceVocabulary {
        public function name(AssuranceFacts $facts): string
        {
            return $facts->allPhishingResistant ? 'acme:strong' : 'acme:standard';
        }
    };

    $resistant = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00'),
    ]);

    $mixed = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00'),
        satisfied('cred-2', FactorStrength::Knowledge, false, '2026-08-11T10:00:00+00:00'),
    ]);

    expect($strict->name($resistant))->toBe('acme:strong')
        ->and($strict->name($mixed))->toBe('acme:standard');
});

it('names one multi-factor credential aal2 rather than aal1', function (): void {
    // A user-verified passkey is possession plus a biometric or PIN: one
    // credential, two factors. Counting credentials alone would call this aal1.
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Possession, false, '2026-08-11T10:00:00+00:00', multiFactor: true),
    ]);

    expect($facts->hasMultiFactorCredential)->toBeTrue()
        ->and((new NistAssuranceVocabulary())->name($facts))->toBe('aal2');
});

it('names one single-factor credential aal1', function (): void {
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Possession, false, '2026-08-11T10:00:00+00:00'),
    ]);

    expect((new NistAssuranceVocabulary())->name($facts))->toBe('aal1');
});

it('derives empty facts for an empty factor list', function (): void {
    $facts = AssuranceFacts::fromFactors([]);

    expect($facts->distinctCredentialCount)->toBe(0)
        ->and($facts->strongest)->toBe(FactorStrength::Recovery)
        ->and($facts->allPhishingResistant)->toBeFalse()
        ->and($facts->hasMultiFactorCredential)->toBeFalse()
        ->and($facts->weakestSatisfiedAt)->toBeNull();
});

it('names zero credentials aal0 under the NIST vocabulary', function (): void {
    expect((new NistAssuranceVocabulary())->name(AssuranceFacts::fromFactors([])))->toBe('aal0');
});

it('derives no assurance at all from a recovery-code-only satisfaction set', function (): void {
    // Spec §7.3: a recovery code never satisfies a policy alone; it grants a
    // restricted recovery-grace session. fromFactors() is a public entry point that
    // accepts a raw satisfaction list, so it must exclude recovery itself rather
    // than trusting the caller to have passed a verdict's usedFactors. Without the
    // filter this set derives one credential and the NIST vocabulary names it aal1.
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-recovery', FactorStrength::Recovery, false, '2026-08-11T10:00:00+00:00'),
    ]);

    expect($facts->distinctCredentialCount)->toBe(0)
        ->and($facts->strongest)->toBe(FactorStrength::Recovery)
        ->and($facts->allPhishingResistant)->toBeFalse()
        ->and($facts->hasMultiFactorCredential)->toBeFalse()
        ->and($facts->weakestSatisfiedAt)->toBeNull()
        ->and((new NistAssuranceVocabulary())->name($facts))->toBe('aal0');
});

it('fails recency for a recovery-code-only satisfaction set', function (): void {
    // The recovery code was redeemed one second ago, and it still must not count as
    // fresh evidence — there is no eligible evidence at all.
    $level = new AssuranceLevel('aal0', AssuranceFacts::fromFactors([
        satisfied('cred-recovery', FactorStrength::Recovery, false, '2026-08-11T10:59:59+00:00'),
    ]));

    expect($level->satisfiesRecency(
        new DateInterval('PT1H'),
        frozenClock('2026-08-11T11:00:00+00:00'),
    ))->toBeFalse();
});

it('lets the real factor alone determine facts when a recovery code is mixed in', function (): void {
    // The recovery code is older, phishing-non-resistant, and a distinct credential.
    // If it leaked through, it would drag recency back to 08:00 and push the count
    // to 2 (which the NIST vocabulary would name aal2). Only the passkey counts.
    $mixed = AssuranceFacts::fromFactors([
        satisfied('cred-recovery', FactorStrength::Recovery, false, '2026-08-11T08:00:00+00:00'),
        satisfied('cred-passkey', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00'),
    ]);

    $passkeyOnly = AssuranceFacts::fromFactors([
        satisfied('cred-passkey', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00'),
    ]);

    expect($mixed)->toEqual($passkeyOnly)
        ->and($mixed->distinctCredentialCount)->toBe(1)
        ->and($mixed->strongest)->toBe(FactorStrength::PossessionStrong)
        ->and($mixed->allPhishingResistant)->toBeTrue()
        ->and($mixed->weakestSatisfiedAt?->format('H:i'))->toBe('10:00')
        ->and((new NistAssuranceVocabulary())->name($mixed))->toBe('aal1');
});

it('fails recency when there is no factor evidence at all', function (): void {
    // A session with no evidence has no freshness to measure, so it can never be
    // fresh enough — it must always be forced to step up (spec §5.3). This branch
    // is security-relevant and was previously unexecuted: inverting it to
    // `return true` left the whole suite green.
    $level = new AssuranceLevel('aal0', AssuranceFacts::fromFactors([]));

    expect($level->satisfiesRecency(
        new DateInterval('PT1H'),
        frozenClock('2026-08-11T11:00:00+00:00'),
    ))->toBeFalse();
});

it('fails recency for any max age when there is no factor evidence', function (): void {
    // Any interval, including a century: the absence of evidence is not freshness.
    $level = new AssuranceLevel('aal0', AssuranceFacts::fromFactors([]));

    foreach (['PT0S', 'PT1H', 'P1D', 'P100Y'] as $spec) {
        expect($level->satisfiesRecency(
            new DateInterval($spec),
            frozenClock('2026-08-11T11:00:00+00:00'),
        ))->toBeFalse();
    }
});

it('passes recency exactly at the max-age boundary', function (): void {
    // The oldest evidence is exactly maxAge old, not older. satisfiesRecency uses
    // >=, so the boundary itself still passes; it only fails once evidence is
    // strictly older than the allowed window.
    $level = new AssuranceLevel('aal2', AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Possession, false, '2026-08-11T09:00:00+00:00'),
    ]));

    $atBoundary = $level->satisfiesRecency(
        new DateInterval('PT2H'),
        frozenClock('2026-08-11T11:00:00+00:00'),
    );

    expect($atBoundary)->toBeTrue();
});
