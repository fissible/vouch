<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use RuntimeException;

/**
 * The operator-facing prerequisite table in docs/operations.md, read as names.
 *
 * Extracted from DoctorPrerequisiteDocsTest so the cases that specify what this must
 * reject can be frozen separately from the thing doing the rejecting. The guard that
 * uses it compares these names against what vouch:doctor reports, in both directions.
 */
final class PrerequisiteTable
{
    /**
     * The prerequisite names the operations table documents.
     *
     * Read from the code spans in the first column, which is a REQUIREMENT rather than a
     * tolerance: every row's name must be a code span, so that the name an operator
     * reads in the document is the name the command prints and can be searched for. A
     * row written as prose is invisible here and fails the comparison -- measured, and
     * that is how the queue row was found describing itself as "Durable asynchronous
     * queue" while the command printed `durable_queue`.
     *
     * @return list<string>
     */
    public static function names(string $operations): array
    {
        if (preg_match('/\| Prerequisite \| Host responsibility \|\n\|[-|]+\|\n((?:\|.*\n)+)/', $operations, $matches) !== 1) {
            throw new RuntimeException('docs/operations.md has no prerequisite table in the expected shape.');
        }

        $names = [];

        foreach (explode("\n", trim($matches[1])) as $line) {
            if (preg_match('/^\| `([^`]+)`/', $line, $cell) === 1) {
                $names[] = $cell[1];
            }
        }

        return $names;
    }
}
