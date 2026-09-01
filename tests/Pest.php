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
    /*
     * Only aal1 and aal2 are derivable. NistAssuranceVocabulary caps at aal2 by
     * design, and aal0 requires zero eligible credentials, which the evidence
     * value refuses to exist with. Fabricating a proof for aal0 or aal3 would
     * silently produce evidence whose derived level contradicts the acr the
     * fixture asked for -- which is the exact class of disagreement 2.4 Task 2a
     * removes, reintroduced through the test helper. Refuse instead.
     */
    if ($level !== 'aal1' && $level !== 'aal2') {
        throw new InvalidArgumentException(
            "No proof can derive {$level}: the shipped vocabulary emits only aal0, aal1 and aal2, "
            . 'and aal0 requires an empty proof. A fixture needing one must ship a custom '
            . 'AssuranceVocabulary, or assert that the requirement fails closed.',
        );
    }

    $factors = [evidenceFactor('password', $at)];

    if ($level === 'aal2') {
        // A second DISTINCT credential, which is what raises the derived level.
        // Two factors sharing one credentialId are one authenticator.
        $factors[] = evidenceFactor('totp', $at, \Fissible\Vouch\Kernel\Factor\FactorStrength::Possession, 'cred-2');
    }

    return sessionProofFrom($userId, $factors);
}

/**
 * Wrap explicit factors as a SESSION proof payload.
 *
 * The provider half is the configured user model's morph class, matching what
 * SessionLifecycle writes and what the Sanctum issuer already uses. evidenceFor()
 * is NOT usable here: it hard-codes a literal provider for the pure value tests,
 * and a session fixture built through it would be refused as a foreign subject.
 *
 * @param  list<\Fissible\Vouch\Kernel\Factor\SatisfiedFactor>  $factors
 * @return array<string, mixed>
 */
function sessionProofFrom(int $userId, array $factors): array
{
    return (new \Fissible\Vouch\Assurance\AssuranceEvidence(
        \Fissible\Vouch\Tokens\SubjectKey::of(configuredUserProvider(), $userId),
        null,
        $factors,
    ))->toArray();
}

/**
 * The provider half of a subject key for the configured user model.
 *
 * Resolves and NARROWS rather than assuming: config returns mixed, and
 * getMorphClass() lives on Eloquent's Model, so an unrelated configured class
 * must fail loudly here rather than at an unrelated assertion later.
 */
function configuredUserProvider(): string
{
    $model = configuredUserModel();

    return (new $model)->getMorphClass();
}

/**
 * Narrow a nullable adapter read to usable evidence, or fail loudly.
 *
 * SessionEvidence::for() is legitimately nullable, so every chained assertion
 * off it is a possible null dereference. Mirrors timestepOf() in
 * TotpFactorTest: a real check that names the problem, not a suppression.
 */
function usableEvidence(?\Fissible\Vouch\Models\AuthSession $session): \Fissible\Vouch\Assurance\AssuranceEvidence
{
    $evidence = \Fissible\Vouch\Sessions\SessionEvidence::for($session);

    if (! $evidence instanceof \Fissible\Vouch\Assurance\AssuranceEvidence) {
        throw new RuntimeException('Expected usable session evidence, got none.');
    }

    return $evidence;
}

/**
 * The configured user model class, narrowed to a class-string.
 *
 * @return class-string<\Illuminate\Database\Eloquent\Model>
 */
function configuredUserModel(): string
{
    $model = stringValue(config('auth.providers.users.model'));

    if ($model === '' || ! is_subclass_of($model, \Illuminate\Database\Eloquent\Model::class)) {
        throw new RuntimeException('auth.providers.users.model is not an Eloquent model.');
    }

    return $model;
}

/** Narrow a nullable timestamp cast, or fail loudly. */
function requiredCarbon(mixed $value): \Illuminate\Support\Carbon
{
    if (! $value instanceof \Illuminate\Support\Carbon) {
        throw new RuntimeException('Expected a Carbon timestamp, got none.');
    }

    return $value;
}

/**
 * The request-bindable session Store.
 *
 * session() returns a SessionManager; Request::setLaravelSession() requires
 * Illuminate\Contracts\Session\Session. The driver is the same Store the
 * manager proxies to, so the id — and the binding — is identical.
 */
function sessionStore(): \Illuminate\Contracts\Session\Session
{
    $store = session()->driver();

    if (! $store instanceof \Illuminate\Contracts\Session\Session) {
        throw new RuntimeException('Expected a session Store.');
    }

    return $store;
}

/** Narrow a query-builder row, or fail loudly. */
function requiredRow(mixed $row): stdClass
{
    if (! $row instanceof stdClass) {
        throw new RuntimeException('Expected a database row, got none.');
    }

    return $row;
}

/**
 * Narrow a decoded JSON body to an array, or fail loudly.
 *
 * @return array<string, mixed>
 */
function jsonBody(mixed $content): array
{
    $decoded = json_decode(stringValue($content), true);

    if (! is_array($decoded)) {
        throw new RuntimeException('Expected a JSON object body.');
    }

    /** @var array<string, mixed> $decoded */
    return $decoded;
}

/**
 * Name evidence with the currently bound vocabulary.
 *
 * Issue #10 deleted AssuranceEvidence::derivedAcr(), which resolved the
 * vocabulary out of the container from inside a value object. A TEST resolving
 * it is a different thing: the test is the caller, and choosing a vocabulary is
 * exactly the caller's job. This helper keeps that choice in one place so the
 * suite states it once rather than at forty call sites.
 */
function nameOf(\Fissible\Vouch\Assurance\AssuranceEvidence $evidence): string
{
    return app(\Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary::class)->name($evidence->facts());
}


/*
 * Markdown block splitting, shared by every documentation suite.
 *
 * Lifted out of ReadmePositioningTest when a second suite needed it. Pest
 * declares test-file functions into ONE global namespace, so a helper defined
 * in a sibling file works only while the whole directory is loaded and dies
 * the moment someone runs a single file -- which is exactly when a
 * documentation assertion is most likely to be run on its own.
 */
/**
 * Blocks of the document: each fenced code block whole, and prose split to the
 * smallest self-contained unit — a paragraph, or a SINGLE list item.
 *
 * Splitting lists per item matters. Treating a whole list as one block lets
 * five unrelated bullets satisfy a boundary between them, which is the token
 * stuffing these assertions exist to avoid. One bullet is the smallest thing
 * that can actually explain a condition and what to do about it.
 *
 * @return list<string>
 */
function docBlocks(string $markdown): array
{
    $blocks = [];

    foreach (preg_split('/((?:```|~~~).*?(?:```|~~~))/s', $markdown, -1, PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY) ?: [] as $chunk) {
        if (preg_match('/^(?:```|~~~)/', trim($chunk)) === 1) {
            $blocks[] = $chunk;

            continue;
        }

        foreach (preg_split('/\n\s*\n/', $chunk) ?: [] as $paragraph) {
            foreach (preg_split('/\n(?=\s*(?:[-*+]|\d+\.)\s)/', $paragraph) ?: [] as $item) {
                if (trim($item) !== '') {
                    $blocks[] = $item;
                }
            }
        }
    }

    /*
     * Re-join a list item with its own indented continuation. The blank-line
     * split above cuts a bullet away from the paragraph that explains it, and
     * the writer wrote one item — leaving them apart would fail an assertion
     * the item genuinely satisfies, and the only way to pass would be to cram
     * the explanation into one line. The tests are supposed to raise the floor,
     * not flatten the prose.
     */
    $joined = [];

    foreach ($blocks as $block) {
        $last = $joined === [] ? null : $joined[count($joined) - 1];
        $continues = $last !== null
            && preg_match('/^\s+\S/', $block) === 1
            && preg_match('/^\s*(?:[-*+]|\d+\.)\s/', $last) === 1;

        if ($continues) {
            $joined[count($joined) - 1] .= "\n\n" . $block;

            continue;
        }

        $joined[] = $block;
    }

    return $joined;
}

/**
 * Is there ONE block matching all of these patterns?
 *
 * For needles where a bare substring would match incidentally — `ui` occurs
 * inside "require" and "build" — the caller supplies a real expression.
 *
 * @param  list<string>  $patterns
 */
function docExplainsTogether(array $patterns, string $markdown): bool
{
    foreach (docBlocks($markdown) as $block) {
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $block) !== 1) {
                continue 2;
            }
        }

        return true;
    }

    return false;
}


function readmePath(): string
{
    // One level from tests/, not two: this helper moved up out of tests/Docs/
    // when a second documentation suite needed it.
    return dirname(__DIR__) . '/README.md';
}

function readmeContents(): string
{
    $raw = @file_get_contents(readmePath());

    if ($raw === false) {
        throw new RuntimeException('README.md does not exist.');
    }

    return $raw;
}

/**
 * @return list<string>
 */
function readmeFences(?string $within = null): array
{
    // Both fence styles GitHub renders. A tilde-fenced example is just as
    // copyable, so leaving it out would put the recipe outside every scan.
    preg_match_all('/(```|~~~).*?\1/s', $within ?? readmeContents(), $matches);

    /** @var list<string> $fences */
    $fences = $matches[0];

    return $fences;
}


/**
 * A fence with its comments removed.
 *
 * Everything that claims a document SHOWS something has to read live code
 * only. A commented example demonstrates nothing and cannot be pasted, and
 * both the route predicate and the ability-map extraction were separately
 * fooled by one before this was shared between them.
 */
function readmeUncommented(string $fence): string
{
    $withoutBlocks = (string) preg_replace('~/\*.*?\*/~s', '', $fence);

    return (string) preg_replace('~^\s*(?://|#).*$~m', '', $withoutBlocks);
}

