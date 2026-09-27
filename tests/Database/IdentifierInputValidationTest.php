<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Enrollment\FirstCredentialRequest;
use Fissible\Vouch\Identifiers\MalformedIdentifier;
use Fissible\Vouch\Identifiers\MalformedIdentifierReason;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Persistence\ValueBoundViolation;
use Fissible\Vouch\Recovery\CredentialRecovery;
use Fissible\Vouch\Recovery\CredentialRecoveryRequest;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Fissible\Vouch\Verification\IdentifierVerificationRequest;
use Fissible\Vouch\Verification\IdentifierVerifier;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * #64 and #65. What a submitted identifier is allowed to be.
 *
 * Identity stopped depending on the engine's collation in #59 and #63, but two
 * ways of reaching somebody else's identifier survived that, both because the
 * DATABASE silently altered a value the application had already accepted.
 *
 * A NUL byte: PostgreSQL truncates a text value at it. Measured -- `ada@x` and
 * `ada@x\0anything` both store as `ada@x` there and the unique index rejects the
 * second as a duplicate, while MySQL and SQLite keep them apart. So one
 * attacker-chosen string reaches somebody else's identifier on one engine and
 * nothing on the other two, which is #63's shape with the engines reversed.
 * Invalid UTF-8 is the same entry point: it reaches IdentifierCanonicalizer and
 * raises Symfony's InvalidArgumentException, unshaped, on user-submitted input.
 *
 * Length: the identifier columns are varchar(255) for a value and varchar(32) for
 * a type, and the engines disagree three ways about anything longer. MySQL under
 * strict sql_mode rejects it. MySQL WITHOUT strict -- a configuration this package
 * documents as expected -- truncates and then treats the next distinct identifier
 * as a duplicate of that truncation, silently merging two accounts. PostgreSQL
 * rejects with 22001. SQLite stores the lot.
 *
 * One defect twice: the application passed on a value it could not store and left
 * the engine to decide what that meant. So the boundary decides instead, and it
 * REFUSES rather than repairing. Stripping the NUL or truncating the tail is
 * precisely how an attacker-chosen string becomes somebody's identifier, so a
 * validator that "fixed" either would cause the bug it exists to prevent.
 *
 * TWO MECHANISMS, DELIBERATELY, because the package already had one of them.
 *
 * Length is `ValueBoundViolation` through the existing valueBounds() declarations,
 * measured in CHARACTERS per column, matching each column's own width -- the unit
 * MySQL and PostgreSQL count varchar in. That mechanism already bounds
 * auth_identifiers.value at 255, and already argues this exact case in its own
 * docblock: refuse rather than truncate, because two values truncating to one
 * collide under a unique index. What it did not bound is everything else an
 * identifier reaches -- auth_identifiers.type, auth_attempts.identifier, and both
 * columns on each of the two proof tables -- and that omission is #65.
 *
 * Bytes are `MalformedIdentifier`: invalid encoding, or a character that cannot
 * appear in an identifier at all. A single length cap in octets was considered and
 * rejected -- a second unit for a question already answered in characters, in
 * conflict with a documented 255-character guarantee, and at 254 octets it would
 * not have protected the varchar(32) type columns, which is where the silent MySQL
 * merge is reproducible.
 *
 * LENGTH IS MEASURED ON THE CANONICAL FORM. Canonicalization changes character
 * count in both directions -- measured: U+0130 lowercases to `i` plus a combining
 * dot, one character becoming two, while a decomposed e-acute composes from two
 * down to one. The fixtures below cross 255 in opposite directions from the same
 * 122 repetitions, so a bound applied to what was submitted is wrong both ways at
 * once.
 *
 * The refusal is an exception rather than a ceremony outcome. `request()` returns
 * void on both ceremonies because the request step must reveal nothing about who
 * exists, so there is no result channel to put this in, and neither malformation is
 * a ceremony outcome -- they are values that cannot name anybody.
 *
 * C1 CONTROLS (U+0080-U+009F) ARE DELIBERATELY UNDECIDED, and that is a choice
 * rather than an oversight. Measured: no engine mangles them -- every C1 stores
 * byte-intact on all three -- so the rationale above, refuse what the engine would
 * silently alter, does not reach them. Nor does PHP: U+0085 NEL is not a line
 * terminator to PCRE with its default convention, so it is not an injection vector
 * the way a newline is. Refusing them has no measured benefit, and blessing them as
 * acceptable would rest on a database measurement that says nothing about a host mail
 * transport. So an implementation may refuse them or not, and both pass.
 *
 * WHAT THE OTHER TWO ENGINES PROVE ABOUT LENGTH: almost nothing. The suite's MySQL
 * runs STRICT_TRANS_TABLES and PostgreSQL rejects with 22001, so both fail closed on
 * an over-long value whether or not any application bound exists -- every length
 * assertion here would pass on them against no bound at all. SQLite is the only
 * engine where these assertions observe this package rather than the engine, which is
 * why one test below turns strict mode off and shows the truncation first.
 *
 * ON READING A FAILURE: the boundary cross product names boundary, malformation and
 * half in its dataset key, but Pest elides that key before the summary line under
 * about 80 columns -- so a single genuine regression appears as one anonymous mark.
 * Run it wider (COLUMNS=200) when one case fails rather than fifty.
 *
 * There is deliberately no test asserting that a refusal writes nothing. With the
 * refusal at construction that question is unreachable rather than answered: no
 * ceremony ever receives the value. A test for it would pass whether or not any
 * validation existed, because constructing a request object touches no database
 * either way, and a test that cannot fail is worse than none -- it reads like
 * coverage.
 */

/** The declared widths, in characters, of the columns an identifier reaches. */
const IDENTIFIER_VALUE_CHARS = 255;
const IDENTIFIER_TYPE_CHARS = 32;

/**
 * Raw characters fit the value column; the canonical form does not.
 *
 * 122 copies of U+0130 -- 135 characters submitted, 257 canonical. A bound applied
 * to what was submitted accepts this and hands the column a value it cannot hold.
 */
function grownIdentifier(): string
{
    return str_repeat("\u{130}", 122) . '@acme.example';
}

/**
 * Raw characters exceed the value column; the canonical form fits.
 *
 * 122 decomposed e-acutes -- 257 characters submitted, 135 canonical. A bound
 * applied to what was submitted REFUSES this, and it is a storable address.
 */
function shrunkIdentifier(): string
{
    return str_repeat("e\u{301}", 122) . '@acme.example';
}

/** A type whose canonical form exceeds varchar(32) although its submitted form does not. */
function grownIdentifierType(): string
{
    return str_repeat("\u{130}", 17);
}

/** An ASCII identifier of exactly $chars characters. */
function identifierOfChars(int $chars): string
{
    return str_repeat('a', $chars - strlen('@acme.example')) . '@acme.example';
}

/*
 * The three request objects, built by helper so a test can discard the result:
 * constructing one is the operation under test, and PHPStan is right that
 * `new X(...)` on a line by itself otherwise has no effect.
 */
function recoveryRequestFor(string $submitted, string $type = 'email'): CredentialRecoveryRequest
{
    return new CredentialRecoveryRequest(
        type: $type,
        submittedIdentifier: $submitted,
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

function verificationRequestFor(string $submitted, string $type = 'email'): IdentifierVerificationRequest
{
    return new IdentifierVerificationRequest(
        type: $type,
        submittedIdentifier: $submitted,
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

function enrollmentRequestFor(string $submitted, string $type = 'email'): FirstCredentialRequest
{
    return new FirstCredentialRequest(
        userId: 1,
        identifierType: $type,
        identifierValue: $submitted,
        password: 'a-first-password',
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

/**
 * The refusal a construction raised, or null if it raised none.
 *
 * Through a callable rather than inline, for a static-analysis reason worth
 * recording: these request objects are pure, so constructing one and discarding it
 * is indistinguishable from doing nothing, and PHPStan says so. The construction IS
 * the operation under test, which a closure expresses and a bare statement cannot.
 *
 * @param  callable(): mixed  $build
 */
function refusalFrom(callable $build): ?MalformedIdentifier
{
    try {
        $build();
    } catch (MalformedIdentifier $thrown) {
        return $thrown;
    }

    return null;
}

function permitInputDelivery(): ArrayOtpDelivery
{
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    return $delivery;
}

/**
 * Every byte sequence a boundary must refuse, keyed by what is wrong with it.
 *
 * One list, because every entry point has to agree about all of them: an
 * implementation refusing the NUL but not a lone continuation byte, or validating
 * recovery and not enrollment, is the state this file exists to prevent.
 *
 * The reason travels as a NAME rather than the enum case, and that is about the
 * handover: a dataset builder touching the enum runs during collection, so before
 * the enum exists Pest reports `DatasetMissing ... no dataset(s) provided` -- an
 * error naming a missing `->with()` when what is missing is a class.
 *
 * @return array<string, array{string, string}>
 */
function malformedIdentifiers(): array
{
    return [
        'trailing nul' => ["ada@acme.example\0", 'ForbiddenCharacter'],
        'embedded nul' => ["ada\0@acme.example", 'ForbiddenCharacter'],
        'newline' => ["ada@acme.example\n", 'ForbiddenCharacter'],
        'tab' => ["ada\t@acme.example", 'ForbiddenCharacter'],
        'delete' => ["ada@acme.example\x7f", 'ForbiddenCharacter'],
        'lone continuation byte' => ["ada@acme.example\x80", 'InvalidEncoding'],
        'truncated sequence' => ["ada@acme.example\xc3", 'InvalidEncoding'],
        'overlong encoding' => ["ada@acme.example\xc0\x80", 'InvalidEncoding'],
        'unpaired surrogate' => ["ada@acme.example\xed\xa0\x80", 'InvalidEncoding'],
    ];
}

/**
 * The same values without their reasons, for a boundary that cannot report one.
 *
 * Derived rather than repeated, so a value added above cannot be missed here.
 *
 * @return array<string, array{string}>
 */
function malformedIdentifierValues(): array
{
    return array_map(static fn (array $case): array => [$case[0]], malformedIdentifiers());
}

/** The enum case that name refers to, resolved when a test runs rather than when it is collected. */
function reasonNamed(string $name): MalformedIdentifierReason
{
    return match ($name) {
        'InvalidEncoding' => MalformedIdentifierReason::InvalidEncoding,
        'ForbiddenCharacter' => MalformedIdentifierReason::ForbiddenCharacter,
        default => throw new RuntimeException('No such malformation reason: ' . $name),
    };
}

/**
 * Every boundary, over every malformed value, on BOTH halves of the identifier.
 *
 * The type is the other half of the unique index and reaches a column of its own,
 * and an earlier version of this file pinned it with one assertion at one boundary
 * -- which a guard installed in a single constructor and nowhere else passed
 * completely. The asymmetry was the hole, so the dataset runs over both halves and
 * all four boundaries.
 *
 * @return array<string, array{string, string, string}>
 */
function malformedAtEveryBoundary(): array
{
    $cases = [];

    foreach (malformedIdentifiers() as $label => [$submitted]) {
        foreach (['recovery', 'verification', 'enrollment', 'model'] as $boundary) {
            $cases[$boundary . ': ' . $label . ' in the value'] = [$boundary, 'value', $submitted];
            $cases[$boundary . ': ' . $label . ' in the type'] = [$boundary, 'type', $submitted];
        }
    }

    return $cases;
}

/** Drive one boundary with a malformation in one half of the identifier. */
function refusalAtBoundary(string $boundary, string $half, string $submitted): ?MalformedIdentifier
{
    $value = $half === 'value' ? $submitted : 'ada@acme.example';
    $type = $half === 'type' ? $submitted : 'email';

    return refusalFrom(static fn (): mixed => match ($boundary) {
        'recovery' => recoveryRequestFor($value, $type),
        'verification' => verificationRequestFor($value, $type),
        'enrollment' => enrollmentRequestFor($value, $type),
        'model' => AuthIdentifier::create([
            'user_id' => 1,
            'type' => $type,
            'value' => $value,
            'verified_at' => null,
        ]),
        default => throw new RuntimeException('No such boundary: ' . $boundary),
    });
}

it('refuses a malformed identifier at every boundary, in either half', function (string $boundary, string $half, string $submitted): void {
    expect(refusalAtBoundary($boundary, $half, $submitted))
        ->toBeInstanceOf(MalformedIdentifier::class);
})->with(malformedAtEveryBoundary());

it('reports which malformation it refused', function (string $submitted, string $reason): void {
    /*
     * The reason, not just the refusal. A host rendering this to somebody has to
     * tell "that address has characters it cannot have" apart from "that is not
     * valid text", and one opaque refusal makes every message the same.
     */
    expect(refusalFrom(static fn (): mixed => recoveryRequestFor($submitted))?->reason)
        ->toBe(reasonNamed($reason));
})->with(malformedIdentifiers());

it('leaves no identifier row behind when the model refuses', function (): void {
    /*
     * Asserted because the guard's placement decides it: moved into a saved hook,
     * after the insert, this is the assertion that fails while every refusal above
     * still passes.
     */
    refusalAtBoundary('model', 'value', "ada@acme.example\0");

    expect(AuthIdentifier::query()->count())->toBe(0);
});

it('bounds the length of every identifier column it reaches', function (): void {
    permitInputDelivery();

    /*
     * The columns the existing bounds did not cover, which is what #65 is. Length is
     * ValueBoundViolation rather than MalformedIdentifier: the package already
     * measures bounds in characters per column and already argues this case in
     * ValueBoundViolation's own docblock, and a second mechanism in a second unit
     * would only give the two a way to disagree.
     */
    expect(static fn (): AuthIdentifier => AuthIdentifier::create([
        'user_id' => 1,
        'type' => identifierOfChars(IDENTIFIER_TYPE_CHARS + 1),
        'value' => 'ada@acme.example',
        'verified_at' => null,
    ]))->toThrow(ValueBoundViolation::class);

    expect(static function (): void {
        app(CredentialRecovery::class)->request(
            recoveryRequestFor(identifierOfChars(IDENTIFIER_VALUE_CHARS + 1)),
        );
    })->toThrow(ValueBoundViolation::class);

    expect(static function (): void {
        app(IdentifierVerifier::class)->request(
            verificationRequestFor(identifierOfChars(IDENTIFIER_VALUE_CHARS + 1)),
        );
    })->toThrow(ValueBoundViolation::class);
});

it('accepts an identifier exactly at the bound', function (): void {
    permitInputDelivery();

    /*
     * The acceptance half. Every refusal above submits one character over, which
     * stays refused however far the bound is tightened -- so without this, capping at
     * 64 would satisfy the whole file. A 255-character address is legitimate and
     * storable: both engines count varchar in characters.
     */
    $request = recoveryRequestFor(identifierOfChars(IDENTIFIER_VALUE_CHARS));

    expect(mb_strlen(canonical($request->submittedIdentifier)))->toBe(IDENTIFIER_VALUE_CHARS);

    app(CredentialRecovery::class)->request($request);

    expect(DB::table('auth_recovery_proofs')->count())->toBe(1);
});

it('measures length on the canonical form, not on what was submitted', function (): void {
    permitInputDelivery();

    /*
     * Both directions, from the same 122 repetitions. The grower is 135 characters
     * submitted and 257 canonical: a bound on the submitted form accepts it and the
     * column cannot hold it. The shrinker is 257 submitted and 135 canonical: a bound
     * on the submitted form refuses a perfectly storable address, written in the
     * decomposed form several input methods produce. Either fixture alone leaves the
     * other direction free.
     */
    expect(mb_strlen(grownIdentifier()))->toBeLessThanOrEqual(IDENTIFIER_VALUE_CHARS)
        ->and(mb_strlen(canonical(grownIdentifier())))->toBeGreaterThan(IDENTIFIER_VALUE_CHARS)
        ->and(mb_strlen(shrunkIdentifier()))->toBeGreaterThan(IDENTIFIER_VALUE_CHARS)
        ->and(mb_strlen(canonical(shrunkIdentifier())))->toBeLessThanOrEqual(IDENTIFIER_VALUE_CHARS);

    expect(static function (): void {
        app(CredentialRecovery::class)->request(recoveryRequestFor(grownIdentifier()));
    })->toThrow(ValueBoundViolation::class);

    DB::table('auth_throttle_counters')->delete();
    DB::table('auth_throttle_tuples')->delete();

    app(CredentialRecovery::class)->request(recoveryRequestFor(shrunkIdentifier()));

    expect(DB::table('auth_recovery_proofs')->count())->toBe(1);
});

it('measures the type column on its own narrower width', function (): void {
    /*
     * varchar(32), not varchar(255), and canonical rather than submitted: 17 copies
     * of U+0130 are 17 characters submitted and 34 canonical. One bound for both
     * halves leaves this reachable, and it is the half where the silent MySQL merge
     * was reproduced -- two 34-character types differing only in the last character
     * both truncate to the same 32 and collide in unique(type, value).
     */
    expect(mb_strlen(grownIdentifierType()))->toBeLessThanOrEqual(IDENTIFIER_TYPE_CHARS)
        ->and(mb_strlen(canonical(grownIdentifierType())))->toBeGreaterThan(IDENTIFIER_TYPE_CHARS);

    expect(static fn (): AuthIdentifier => AuthIdentifier::create([
        'user_id' => 1,
        'type' => grownIdentifierType(),
        'value' => 'ada@acme.example',
        'verified_at' => null,
    ]))->toThrow(ValueBoundViolation::class);
});

/**
 * Characters that look suspicious and are not: each was measured storing
 * byte-intact on MySQL, PostgreSQL and SQLite.
 *
 * @return array<string, array{string}>
 */
function acceptableIdentifiers(): array
{
    return [
        'latin with acute' => ["jos\u{e9}@acme.example"],
        'decomposed acute' => ["jose\u{301}@acme.example"],
        'cjk' => ["\u{5c71}\u{7530}@acme.example"],
        'arabic' => ["\u{627}\u{62d}\u{645}\u{62f}@acme.example"],
        'zero-width non-joiner in persian' => ["\u{645}\u{6cc}\u{200c}\u{62e}\u{648}\u{627}\u{646}@acme.example"],
        'zero-width joiner in an emoji sequence' => ["\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}@acme.example"],
        'right-to-left mark' => ["ada\u{200f}@acme.example"],
        'byte order mark' => ["\u{feff}ada@acme.example"],
        'soft hyphen' => ["ada\u{ad}@acme.example"],
        'trailing space' => ['ada@acme.example '],
    ];
}

it('accepts an identifier that only looks suspicious', function (string $value): void {
    /*
     * The ceiling on the character policy, and the reason it needs one: the easiest
     * wrong shape is a sweep of everything Unicode calls "other", which refuses every
     * Persian and Indic zero-width non-joiner, every emoji joiner sequence, every
     * right-to-left mark and every byte order mark -- while passing a file whose
     * acceptable list is all letters and combining marks.
     *
     * The trailing space is here for a different reason: #63 settled that trimming is
     * an open identity-policy question and that a padded spelling is a DIFFERENT
     * identifier rather than an invalid one. A validator that trimmed or refused it
     * would reopen that, and would otherwise pass everything here.
     */
    $request = recoveryRequestFor($value);

    expect($request->submittedIdentifier)->toBe($value);
})->with(acceptableIdentifiers());

it('refuses a malformed identifier at the identify step', function (string $submitted): void {
    permitInputDelivery();

    /*
     * The fifth entry point, and the one that builds none of the request objects
     * above: AuthFlow reads the identifier straight out of the submitted input and
     * writes it to auth_attempts.identifier, which is varchar(255) and unbounded. It
     * also hands that value to the issuance throttle, whose key canonicalizes it, so
     * invalid UTF-8 reaching this step raises Symfony's exception out of a throttle
     * lookup rather than being refused.
     *
     * A refused screen, not the unknown-identifier path. An unknown identifier
     * deliberately continues and offers a challenge so the step cannot become an
     * account-existence oracle; malformed input is not an account either way, and
     * continuing would spend an issuance budget on a value that cannot be anyone.
     */
    $handle = beginIdentifierFlow('m');

    $result = app(\Fissible\Vouch\Flow\AuthFlow::class)->advance(new \Fissible\Vouch\Flow\FlowRequest(
        $handle,
        'submit',
        ['identifier' => $submitted],
        identifierFlowBinding('m'),
    ));

    expect($result)->toBeInstanceOf(\Fissible\Vouch\Flow\Continuing::class);

    $screen = $result instanceof \Fissible\Vouch\Flow\Continuing ? $result->screen : null;
    $attempt = requiredRow(DB::table('auth_attempts')->where('handle', $handle)->first());

    expect($screen?->step)->toBe(\Fissible\Vouch\Kernel\Screen\AuthStep::Identify)
        ->and($screen?->errors)->not->toBe([])
        /*
         * Null, not merely different from what was submitted: an implementation that
         * refused the screen and still wrote a stripped or truncated value would
         * satisfy "different" while leaving the column holding attacker-chosen text.
         */
        ->and($attempt->user_id)->toBeNull()
        ->and($attempt->identifier)->toBeNull();
})->with(malformedIdentifierValues());

it('advances the identify step for an ordinary identifier', function (): void {
    permitInputDelivery();

    /*
     * The positive control for the test above. A refused identify screen is also what
     * an empty identifier produces, so without this a flow refusing every submission
     * would satisfy every assertion there.
     */
    AuthIdentifier::create([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => now(),
    ]);

    $handle = beginIdentifierFlow('n');

    app(\Fissible\Vouch\Flow\AuthFlow::class)->advance(new \Fissible\Vouch\Flow\FlowRequest(
        $handle,
        'submit',
        ['identifier' => 'ada@acme.example'],
        identifierFlowBinding('n'),
    ));

    expect(DB::table('auth_attempts')->where('handle', $handle)->value('user_id'))->toBe(1);
});

it('still serves an ordinary identifier end to end', function (): void {
    permitInputDelivery();

    /*
     * The positive control for the whole file. Almost every assertion here is a
     * refusal, and a validator that refused everything satisfies all of them -- so
     * one test carries a real address through the ceremony the refusals guard.
     */
    AuthIdentifier::create([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => now(),
    ]);

    app(CredentialRecovery::class)->request(recoveryRequestFor('ada@acme.example'));

    expect(DB::table('auth_recovery_proofs')->count())->toBe(1);
});

it('bounds the length of the type half on the proof tables too', function (): void {
    permitInputDelivery();

    /*
     * The type half on the two proof tables, which the bound above pins only on
     * auth_identifiers. Both are varchar(32) and both are reachable through their
     * ceremony, so a bound declared on one model and not the others is invisible --
     * measured: dropping it from both proof models passed this file entirely.
     */
    expect(static function (): void {
        app(CredentialRecovery::class)->request(recoveryRequestFor('ada@acme.example', identifierOfChars(IDENTIFIER_TYPE_CHARS + 1)));
    })->toThrow(ValueBoundViolation::class);

    expect(static function (): void {
        app(IdentifierVerifier::class)->request(verificationRequestFor('ada@acme.example', identifierOfChars(IDENTIFIER_TYPE_CHARS + 1)));
    })->toThrow(ValueBoundViolation::class);
});

it('refuses an over-length identifier at the identify step, on its own channel', function (): void {
    permitInputDelivery();

    /*
     * The fifth column, auth_attempts.identifier, and the last of the five #65 names.
     * Nothing else here submits a LONG value to this step -- the malformed-bytes test
     * beside it submits only bad bytes -- so without this the identify step is covered
     * for #64 and not at all for #65.
     *
     * A refused screen, not an escaping exception, and that is the point of the test
     * rather than an incidental assertion. Nothing in src catches ValueBoundViolation,
     * so left alone it travels out of advance() to the host's error handler: a
     * malformed byte at this step would render a refusal and one character too many
     * would render a 500. The step has a refusal channel and both malformations
     * should use it.
     */
    $handle = beginIdentifierFlow('o');

    $result = app(\Fissible\Vouch\Flow\AuthFlow::class)->advance(new \Fissible\Vouch\Flow\FlowRequest(
        $handle,
        'submit',
        ['identifier' => identifierOfChars(IDENTIFIER_VALUE_CHARS + 1)],
        identifierFlowBinding('o'),
    ));

    expect($result)->toBeInstanceOf(\Fissible\Vouch\Flow\Continuing::class);

    $screen = $result instanceof \Fissible\Vouch\Flow\Continuing ? $result->screen : null;
    $attempt = requiredRow(DB::table('auth_attempts')->where('handle', $handle)->first());

    expect($screen?->step)->toBe(\Fissible\Vouch\Kernel\Screen\AuthStep::Identify)
        ->and($screen?->errors)->not->toBe([])
        ->and($attempt->user_id)->toBeNull()
        ->and($attempt->identifier)->toBeNull();
});

it('is what closes the merge on a host without strict sql_mode', function (): void {
    if (DB::connection()->getDriverName() !== 'mysql') {
        $this->markTestSkipped('Only MySQL truncates instead of refusing, and only without strict sql_mode.');
    }

    /*
     * The configuration #65 is actually about, which no other test here reaches.
     *
     * The suite's MySQL runs STRICT_TRANS_TABLES, so an over-long value is rejected by
     * the engine with 1406 and every length assertion in this file would pass with no
     * application bound at all. That makes the other two engines' green runs prove
     * nothing about this code: they fail closed on their own. Only a host WITHOUT
     * strict mode -- which PROJECT.md records as expected -- silently truncates, and
     * that is where two distinct identifiers become one account.
     *
     * So: turn strict mode off for this session, show the engine really does truncate
     * rather than refuse, and then show the application refuses anyway. The first half
     * is the control -- without it, this test would pass on a strict connection and
     * prove nothing.
     */
    DB::statement("set session sql_mode=''");

    DB::table('auth_attempts')->insert([
        'handle' => str_repeat('c', 32),
        'state' => 'initiated',
        'version' => 1,
        'identifier' => identifierOfChars(IDENTIFIER_VALUE_CHARS + 40),
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    $stored = stringValue(DB::table('auth_attempts')->where('handle', str_repeat('c', 32))->value('identifier'));

    expect(mb_strlen($stored))->toBe(IDENTIFIER_VALUE_CHARS, 'the engine should have truncated, silently');

    permitInputDelivery();

    // And the application refuses the same value rather than letting it truncate.
    expect(static function (): void {
        app(CredentialRecovery::class)->request(recoveryRequestFor(identifierOfChars(IDENTIFIER_VALUE_CHARS + 40)));
    })->toThrow(ValueBoundViolation::class);
});
