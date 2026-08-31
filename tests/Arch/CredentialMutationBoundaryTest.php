<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Arch;

use Fissible\Vouch\Credentials\CredentialMutation;
use Fissible\Vouch\Credentials\CredentialWriterManifest;
use Fissible\Vouch\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;

/**
 * 2.4 Task 5b — the boundary that keeps the classification honest.
 *
 * "Route every credential write through one facade" is the WRONG goal, and
 * stating it that way is how this goes wrong. `DatabaseAttemptStore::apply()`
 * handles both `DisableCredential` and `AdvanceCredentialTimestep`, and the
 * latter advances `last_used_timestep` on every successful TOTP verification
 * because it IS the replay guard. Route both through a revoking path and every
 * TOTP login revokes the user's own tokens.
 *
 * What this file can and cannot do, stated plainly so a reader calibrates:
 *
 *   IT CAN detect that a file writes credential rows and is unclassified, so a
 *   NEW writer cannot ship silently. That is a discovery guard.
 *
 *   IT CANNOT prove a site calls the right entry point — a file-level manifest
 *   cannot certify a site-level decision, and `DatabaseAttemptStore` contains
 *   one write of each kind. That proof is BEHAVIOURAL and lives in
 *   tests/Database/CredentialWriterRoutingTest.php, which drives the real
 *   flow, the real drivers and real self-service. If that file is ever deleted,
 *   this one stops meaning very much.
 *
 * Detection is done over PHP TOKENS rather than raw text, so a table name in a
 * comment or a docblock is not a writer.
 *
 * ITS SCOPE, stated rather than implied, because a guard that is trusted beyond
 * its reach is worse than no guard: this recognises the syntax the package uses
 * TODAY. A statement counts when it performs a write call and either names
 * AuthCredential or 'auth_credentials', or touches a column that exists only on
 * that table — currently disabled_at, last_used_timestep and secret, which is
 * what makes a bare `$credential->update(['secret' => ...])` detectable. A
 * `$credential->save()`, or a delete naming none of those, would still EVADE
 * it. That is a real hole, and it is accepted knowingly: closing it needs
 * dataflow analysis to know what a variable refers to, and the alternative
 * heuristics considered (matching variable names, matching any update in a file
 * that mentions credentials anywhere) each failed in the other direction --
 * the file-level version reported AuthFlow, CredentialRecovery and
 * CredentialSelfService, none of which writes a credential row.
 *
 * WHAT CAN PASS UNDETECTED. The list is REPRESENTATIVE, not exhaustive — that
 * distinction is the point, because an exhaustive-sounding list is exactly how a
 * guard gets trusted past its reach:
 *
 *   - a write in one of the two PROTOCOL_FILES, which are excluded by name;
 *   - raw SQL: WRITE_CALLS is a fixed list of query-builder and Eloquent
 *     methods, so `DB::statement('UPDATE auth_credentials SET secret = ...')`
 *     passes even though it names the table outright. The package does use raw
 *     DDL in migrations, so this is not hypothetical;
 *   - any write API outside that fixed list, present or future;
 *   - a bare `$credential->save()`, or a delete, naming none of the credential
 *     markers;
 *   - a new write in an already-counted STATEMENT, such as another arm inside
 *     DatabaseAttemptStore's match — mitigated by the dispatch-type pin, and by
 *     the TOTP and recovery tests asserting those arms leave `secret` alone;
 *   - a new write accompanied by a fabricated manifest line naming any real
 *     method of that file.
 *
 * Treat it as a current-syntax discovery guard, not a general credential-write
 * detector, and never as proof of routing.
 *
 * THE DISTINCTION THAT MATTERS, because it is easy to collapse: the behavioural
 * routing tests prove routing FOR THE WRITERS THIS GUARD FINDS. They do not
 * close the detection gap. A future credential write using an unrecognised API
 * — raw SQL above all — would never be discovered here, so it would never be
 * given a routing test either, and BOTH halves would stay green while it
 * bypassed the protocol entirely.
 *
 * So the two mechanisms do not cover for each other, and the residual risk is
 * detection, not routing. Anyone extending the package with a new way of
 * writing credentials must add it to WRITE_CALLS themselves; nothing here will
 * ask them to.
 */
final class CredentialMutationBoundaryTest extends TestCase
{
    private const WRITE_CALLS = [
        'create', 'insert', 'insertGetId', 'insertOrIgnore', 'update', 'updateOrCreate',
        'upsert', 'firstOrCreate', 'save', 'delete', 'forceDelete', 'increment', 'decrement',
    ];

    /** @return list<string> */
    private function productionFiles(): array
    {
        $root = (string) realpath(__DIR__ . '/../../src');
        $files = [];
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root));

        foreach ($iterator as $file) {
            if ($file instanceof \SplFileInfo && $file->getExtension() === 'php') {
                $files[] = str_replace($root . '/', '', (string) $file->getRealPath());
            }
        }

        sort($files);

        return $files;
    }

    /**
     * Files containing a STATEMENT that writes credential rows.
     *
     * Statement-level, not file-level. A file-level rule reported AuthFlow,
     * CredentialRecovery and CredentialSelfService as writers: all three
     * reference AuthCredential to READ, and all three perform writes against
     * other tables, and a file-level scan cannot tell those apart. Forcing a
     * classification for a non-writer is not harmless — it pads the manifest
     * until it stops meaning anything.
     *
     * A statement counts when it performs a write call AND either names the
     * credential model or table, or touches a column that exists only on
     * auth_credentials. The second half is what catches the bare instance form,
     * `$credential->update(['disabled_at' => ...])`, whose statement never
     * names the model — the form a statement-level rule would otherwise miss,
     * and missing a writer is the failure that matters.
     *
     * Counted per SITE, not per file. The contract classifies write SITES, and
     * a file-keyed guard lets a new write be added to an already-classified
     * file without anything failing — which is exactly how a new password or
     * TOTP rewrite would bypass routing while this file stayed green.
     *
     * @return array<string, int> file => number of credential-write statements
     */
    private function filesWritingCredentials(): array
    {
        $root = (string) realpath(__DIR__ . '/../../src');
        $writers = [];

        foreach ($this->productionFiles() as $relative) {
            /*
             * Only the two files that ARE the protocol, named individually. An
             * unbounded `Credentials/` exclusion would let a new direct
             * credential write be placed beside the facade and pass both the
             * discovery check and the count check — the guard excusing exactly
             * the directory it is guarding.
             */
            if (in_array($relative, self::PROTOCOL_FILES, true)) {
                continue;
            }

            $tokens = array_values(array_filter(
                token_get_all((string) file_get_contents($root . '/' . $relative)),
                static fn (array|string $token): bool => ! is_array($token)
                    || ! in_array($token[0], [T_COMMENT, T_DOC_COMMENT, T_INLINE_HTML, T_WHITESPACE], true),
            ));

            $sites = 0;
            $statement = [];
            foreach ($tokens as $token) {
                if ($token === ';') {
                    if ($this->statementWritesCredentials($statement)) {
                        $sites++;
                    }

                    $statement = [];

                    continue;
                }

                $statement[] = $token;
            }

            if ($sites > 0) {
                $writers[$relative] = $sites;
            }
        }

        ksort($writers);

        return $writers;
    }

    /**
     * Columns that exist only on auth_credentials, so a write touching one is a
     * credential write whatever the receiver is called.
     */
    private const CREDENTIAL_ONLY_COLUMNS = ['disabled_at', 'last_used_timestep', 'secret'];

    /** The protocol itself: it names credentials by definition. Nothing else here does. */
    private const PROTOCOL_FILES = [
        'Credentials/CredentialMutation.php',
        'Credentials/CredentialWriterManifest.php',
    ];

    /** @param array<int, array{0: int, 1: string}|string> $statement */
    private function statementWritesCredentials(array $statement): bool
    {
        $namesCredentials = false;
        $writes = false;

        foreach ($statement as $index => $token) {
            if (! is_array($token)) {
                continue;
            }

            if ($token[0] === T_CONSTANT_ENCAPSED_STRING) {
                $literal = trim($token[1], "'\"");

                if ($literal === 'auth_credentials'
                    || in_array($literal, self::CREDENTIAL_ONLY_COLUMNS, true)) {
                    $namesCredentials = true;
                }
            }

            if ($token[0] === T_STRING) {
                if ($token[1] === 'AuthCredential') {
                    $namesCredentials = true;
                }

                if (in_array($token[1], self::WRITE_CALLS, true) && $this->isCall($statement, $index)) {
                    $writes = true;
                }
            }
        }

        return $namesCredentials && $writes;
    }

    /** @param array<int, array{0: int, 1: string}|string> $tokens */
    private function isCall(array $tokens, int $index): bool
    {
        // A method name only counts when it is actually invoked, so a property
        // or a declaration named `update` is not mistaken for a write.
        for ($next = $index + 1, $count = count($tokens); $next < $count; $next++) {
            $token = $tokens[$next];

            if (is_array($token) && $token[0] === T_WHITESPACE) {
                continue;
            }

            return $token === '(';
        }

        return false;
    }

    #[Test]
    public function every_credential_writer_is_classified(): void
    {
        /*
         * The guard that catches the NEXT writer — the one nobody in this
         * conversation has seen. An unclassified writer gets no safe default:
         * defaulting to additive would silently skip a revocation, and
         * defaulting to revoking would reintroduce the TOTP problem. It fails,
         * and a human decides.
         */
        $classified = CredentialWriterManifest::classified();
        $unclassified = array_values(array_diff(
            array_keys($this->filesWritingCredentials()),
            array_keys($classified),
        ));

        self::assertSame([], $unclassified, sprintf(
            "These files write credential rows without a classification: %s.\n"
            . 'Add each to CredentialWriterManifest naming the mutation kind, and add a '
            . 'behavioural test to CredentialWriterRoutingTest that drives the real path. '
            . 'Do not guess: an additive misclassification skips a revocation, and a '
            . "revoking one makes an ordinary login revoke the user's tokens.",
            implode(', ', $unclassified),
        ));
    }

    #[Test]
    public function every_write_site_is_classified_not_merely_every_file(): void
    {
        /*
         * The guard that catches a write ADDED to a file somebody already
         * classified. A file-keyed manifest is satisfied the moment the file
         * appears once, so a second write in PasswordFactor — a rewrite of
         * `secret`, say — would ship unrouted with this suite green.
         *
         * Each file therefore declares one classification PER SITE, and the
         * counts must agree. The numbers are not decoration: they are the only
         * thing that changes when a writer is added.
         */
        $detected = $this->filesWritingCredentials();
        $classified = CredentialWriterManifest::classified();

        foreach ($detected as $file => $sites) {
            self::assertArrayHasKey($file, $classified);
            self::assertCount($sites, $classified[$file], sprintf(
                '"%s" has %d credential-write site(s) but declares %d classification(s). '
                . 'Classify each site, and add a behavioural test driving it.',
                $file,
                $sites,
                count($classified[$file] ?? []),
            ));
        }
    }

    #[Test]
    public function the_manifest_accounts_for_every_measured_site(): void
    {
        /*
         * The whole-corpus check. A count that drifts without anyone noticing
         * means the classification stopped describing the code.
         *
         * FIFTEEN detected statements for SIXTEEN conceptual writes, and the
         * difference is not an error: DatabaseAttemptStore::apply() performs
         * both of its credential writes inside one `match` expression, so they
         * share a single statement and this detector — which splits on `;` —
         * cannot separate them. Counting write CALLS instead would overcount,
         * because that same match also updates auth_challenges.
         *
         * That file's one entry therefore has to name BOTH mutations, which is
         * asserted separately. Recorded here rather than rounded away, so a
         * reader who counts sixteen in the plan and fifteen here knows why.
         */
        $total = array_sum(array_map('count', CredentialWriterManifest::classified()));

        self::assertSame(15, $total);
        self::assertSame(array_sum($this->filesWritingCredentials()), $total);
    }

    #[Test]
    public function the_detector_finds_the_writers_this_task_measured(): void
    {
        /*
         * A discovery step that silently finds nothing passes forever. These
         * six are the writers the detector must reach — five measured by hand
         * before the manifest existed, and OtpFactor alongside them —
         * so the detector must at minimum reach them — including the attempt
         * store, which writes through the query builder rather than the model.
         */
        $found = array_keys($this->filesWritingCredentials());

        foreach ([
            'Attempts/DatabaseAttemptStore.php',
            'Enrollment/FirstCredentialEnrollment.php',
            'Factors/Drivers/OtpFactor.php',
            'Factors/Drivers/PasswordFactor.php',
            'Factors/Drivers/RecoveryCodeFactor.php',
            'Factors/Drivers/TotpFactor.php',
        ] as $expected) {
            self::assertContains($expected, $found);
        }
    }

    #[Test]
    public function the_manifest_classifies_nothing_that_does_not_write(): void
    {
        /*
         * The mirror failure: a manifest that drifts ahead of the code stops
         * being evidence. A stale entry makes the test above pass for a writer
         * that no longer exists.
         */
        $stale = array_values(array_diff(
            array_keys(CredentialWriterManifest::classified()),
            array_keys($this->filesWritingCredentials()),
        ));

        self::assertSame([], $stale);
    }

    #[Test]
    public function the_attempt_stores_two_writes_are_both_named(): void
    {
        /*
         * Pinned by name, because this file is the reason the task exists and
         * because its second write is a trap wearing a misleading name.
         *
         * `AdvanceCredentialTimestep` is the TOTP replay guard. `DisableCredential`
         * SOUNDS like a revocation and is not: its only emitter is
         * RecoveryCodeFactor burning a single-use code on a SUCCESSFUL RECOVERY VERIFICATION, which yields recovery grace rather than a host-guard login.
         * Both are bookkeeping, and a manifest entry naming only one of them
         * would let the other be classified by its identifier — which is
         * exactly the reasoning that revokes a user's tokens when they log in.
         */
        $classified = CredentialWriterManifest::classified();

        self::assertArrayHasKey('Attempts/DatabaseAttemptStore.php', $classified);
        $reasons = implode(' | ', $classified['Attempts/DatabaseAttemptStore.php']);

        self::assertStringContainsString('AdvanceCredentialTimestep', $reasons);
        self::assertStringContainsString('DisableCredential', $reasons);
        self::assertStringContainsString('bookkeeping', $reasons);
    }

    #[Test]
    public function the_attempt_stores_dispatch_types_are_pinned(): void
    {
        /*
         * The hole the site COUNT cannot close. DatabaseAttemptStore::apply()
         * dispatches on `$mutation instanceof ...` inside one match expression,
         * so a NEW credential-writing arm added there is still one statement,
         * still one manifest entry, and still names both existing mutations —
         * every other assertion in this file passes while an unclassified
         * writer ships.
         *
         * So the dispatch types are pinned. Precisely what this parses, since
         * the name could overstate it: EVERY `instanceof` in the class, not the
         * match arms specifically, and both bare and fully-qualified names.
         * That is deliberately conservative, so an unrelated future type check
         * also fails here and has to be added to the list.
         *
         * What it still cannot see is a change INSIDE an existing arm. The
         * DisableCredential arm growing to rewrite `secret` as well as
         * disabled_at keeps this set, the statement count and the manifest
         * entry identical; that case is covered behaviourally instead, by the
         * recovery-consumption test asserting the secret is untouched.
         */
        $source = (string) file_get_contents(__DIR__ . '/../../src/Attempts/DatabaseAttemptStore.php');
        // Fully-qualified arms too: `instanceof \Fissible\...\NewMutation`
        // would otherwise slip past a bare-identifier pattern and keep the
        // pinned set intact, which is precisely the bypass this guards.
        preg_match_all('/instanceof\s+(\\\\?(?:[A-Za-z_][A-Za-z0-9_]*\\\\)*[A-Za-z_][A-Za-z0-9_]*)/', $source, $matches);

        $arms = array_values(array_unique(array_map(
            static fn (string $name): string => ltrim(substr(strrchr('\\' . $name, '\\') ?: '', 1), '\\'),
            $matches[1],
        )));
        sort($arms);

        self::assertSame(
            ['AdvanceCredentialTimestep', 'AuthAttempt', 'ConsumeChallenge', 'DisableCredential'],
            $arms,
            'A mutation arm was added to or removed from DatabaseAttemptStore. If it writes '
            . 'auth_credentials, classify it in CredentialWriterManifest and drive it from '
            . 'CredentialWriterRoutingTest before updating this list.',
        );
    }

    #[Test]
    public function the_facade_offers_no_general_purpose_entry_point(): void
    {
        /*
         * Three named methods, not one method with a flag. A caller must SAY
         * which kind of mutation it performs, and the dangerous case cannot be
         * reached by forgetting an argument or passing the wrong enum.
         *
         * The structural half of the guard: the manifest records the decision,
         * the routing tests prove it was made correctly, and the API shape stops
         * it from being skipped.
         */
        $methods = [];
        foreach ((new ReflectionClass(CredentialMutation::class))->getMethods() as $method) {
            if ($method->isPublic() && ! $method->isConstructor()) {
                $methods[] = $method->getName();
            }
        }
        sort($methods);

        self::assertSame(['additive', 'revoking', 'subjectWide'], $methods);
    }

    #[Test]
    public function every_classification_names_a_method_that_exists(): void
    {
        /*
         * Ties each entry to real code. The manifest is COUNT-based, so on its
         * own a new write in an existing file could be waved through by adding
         * any extra line of prose — the count would agree and nothing would
         * check that the new entry described anything.
         *
         * Requiring each entry to name a method that actually exists in that
         * file raises the floor: a fabricated entry has to name a real method,
         * and naming one means looking at the file.
         *
         * Its remaining limit, stated accurately rather than minimised: this
         * proves each entry MENTIONS a real method, not that it identifies the
         * write site it stands for. So a new write — even one in a brand new
         * method — can be waved through by adding a line that names any other
         * real method in that file. That is broader than "a second write inside
         * an already-named method", which is how an earlier version of this
         * comment put it, and it is wrong to read this test as more than it is.
         *
         * Closing it properly would need site markers in production source that
         * only tests read, which is a maintenance trap of its own. The
         * behavioural routing tests are what actually prove routing; this is a
         * discovery guard and nothing more.
         */
        $root = (string) realpath(__DIR__ . '/../../src');

        foreach (CredentialWriterManifest::classified() as $file => $reasons) {
            $source = (string) file_get_contents($root . '/' . $file);
            preg_match_all('/function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/', $source, $found);
            $methods = $found[1];

            foreach ($reasons as $index => $reason) {
                $named = array_values(array_filter(
                    $methods,
                    static fn (string $method): bool => str_contains($reason, $method . '('),
                ));

                self::assertNotSame([], $named, sprintf(
                    '"%s" site %d names no method of that file. Write the classification as '
                    . '"methodName(): <kind> because ...", so the entry points at real code.',
                    $file,
                    $index,
                ));
            }
        }
    }

    #[Test]
    public function every_classification_names_a_real_mutation_kind(): void
    {
        foreach (CredentialWriterManifest::classified() as $file => $reasons) {
            foreach ($reasons as $index => $reason) {
                self::assertMatchesRegularExpression(
                    '/\b(additive|revoking|subjectWide|bookkeeping)\b/',
                    $reason,
                    sprintf('"%s" site %d is classified without naming a mutation kind.', $file, $index),
                );
                self::assertGreaterThan(30, strlen(trim($reason)), sprintf(
                    '"%s" site %d is classified with a reason too short to be one.',
                    $file,
                    $index,
                ));
            }
        }
    }
}
