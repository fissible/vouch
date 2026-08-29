<?php

declare(strict_types=1);

/*
 * Database-backed suites boot Testbench. Kernel and Arch suites deliberately
 * do NOT — they are framework-free and must stay fast and unaffected by
 * anything Laravel does.
 */
uses(\Fissible\Vouch\Tests\TestCase::class)->in('Database', 'Concurrency', 'Factors', 'Flow', 'Sessions', 'Http', 'Recovery', 'Console', 'Authorization', 'Docs', 'Tokens', 'Assurance');

/**
 * Narrow a query builder's mixed value to a string without a bare cast.
 *
 * Shared here because Pest test files declare into one global function
 * namespace, so a per-file copy collides at load time.
 */
function stringValue(mixed $value): string
{
    return is_scalar($value) ? (string) $value : '';
}

/**
 * Build one satisfied factor for assurance-evidence tests.
 *
 * Shared here rather than in a sibling test file: Pest declares test-file
 * functions into one global namespace, so a helper defined next door works
 * only while the whole directory is loaded and dies the moment someone runs a
 * single file.
 */
function evidenceFactor(
    string $id = 'password',
    string $at = '2026-08-29T10:00:00+00:00',
    \Fissible\Vouch\Kernel\Factor\FactorStrength $strength = \Fissible\Vouch\Kernel\Factor\FactorStrength::Knowledge,
    string $credentialId = 'cred-1',
): \Fissible\Vouch\Kernel\Factor\SatisfiedFactor {
    return new \Fissible\Vouch\Kernel\Factor\SatisfiedFactor(
        factorId: $id,
        credentialId: $credentialId,
        kind: \Fissible\Vouch\Kernel\Factor\FactorKind::Knowledge,
        strength: $strength,
        isMultiFactor: false,
        userVerified: false,
        phishingResistant: false,
        authenticatorId: null,
        satisfiedAt: new DateTimeImmutable($at),
    );
}

/**
 * @param list<\Fissible\Vouch\Kernel\Factor\SatisfiedFactor> $factors
 */
function evidenceFor(array $factors, ?string $tenantId = null, int $userId = 7): \Fissible\Vouch\Assurance\AssuranceEvidence
{
    return new \Fissible\Vouch\Assurance\AssuranceEvidence(
        \Fissible\Vouch\Tokens\SubjectKey::of('App\\Models\\User', $userId),
        $tenantId,
        $factors,
    );
}

/**
 * The persisted proof payload for a session fixture at a given level.
 *
 * Built through the real value object rather than as a hand-written array, so
 * that fixtures across the suite cannot drift from whatever serialization the
 * implementation actually lands on. A hand-rolled payload here would have to be
 * corrected in a dozen files the first time a field is added.
 *
 * @return array<string, mixed>
 */
function sessionProof(int $userId = 7, string $level = 'aal2', string $at = '2026-08-13T10:00:00+00:00'): array
{
    $factors = [evidenceFactor('password', $at)];

    if ($level === 'aal2' || $level === 'aal3') {
        // A second DISTINCT credential, which is what raises the derived level.
        // Two factors sharing one credentialId are one authenticator.
        $factors[] = evidenceFactor('totp', $at, \Fissible\Vouch\Kernel\Factor\FactorStrength::Possession, 'cred-2');
    }

    return evidenceFor(
        $factors,
        null,
        $userId,
    )->toArray();
}
