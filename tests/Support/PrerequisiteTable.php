<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use League\CommonMark\Environment\Environment;
use League\CommonMark\Extension\CommonMark\CommonMarkCoreExtension;
use League\CommonMark\Extension\CommonMark\Node\Inline\Code;
use League\CommonMark\Extension\Table\Table;
use League\CommonMark\Extension\Table\TableExtension;
use League\CommonMark\Extension\Table\TableSection;
use League\CommonMark\Input\MarkdownInput;
use League\CommonMark\Parser\MarkdownParser;
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
     * row written as prose, or with text beside its code span, is refused with the
     * full source row before the comparison. Skipping it left invented prerequisites
     * invisible to the comparison, even though an operator could read them.
     *
     * @return list<string>
     */
    public static function names(string $operations): array
    {
        /*
         * #95. Membership belongs to the same parser the renderer uses. Requiring
         * leading pipes truncated the table at indented or pipe-less rows; widening
         * the capture to two pipes still missed "Unreported prerequisite | Must
         * configure this too.". Neither pattern describes the table a reader sees.
         * The source header only selects the table; its parsed body supplies EVERY
         * row, and its inline nodes decide whether the first cell is only code.
         */
        $environment = new Environment;
        $environment->addExtension(new CommonMarkCoreExtension);
        $environment->addExtension(new TableExtension);
        $document = (new MarkdownParser($environment))->parse($operations);
        $lines = iterator_to_array((new MarkdownInput($operations))->getLines());

        foreach ($document->iterator() as $table) {
            if (! $table instanceof Table) {
                continue;
            }

            $startLine = $table->getStartLine();

            if ($startLine === null || trim($lines[$startLine]) !== '| Prerequisite | Host responsibility |') {
                continue;
            }

            $names = [];
            // CommonMark gives the table a source position, but not its rows.
            // TableParser builds one body row per line after the header/separator.
            // Preserve those original lines, including indentation, for refusals.
            $rowLine = $startLine + 2;

            foreach ($table->children() as $section) {
                if (! $section instanceof TableSection || ! $section->isBody()) {
                    continue;
                }

                foreach ($section->children() as $row) {
                    $name = $row->firstChild()?->firstChild();

                    if (! $name instanceof Code || $name->next() !== null) {
                        throw new RuntimeException('Prerequisite name must be a code span: ' . $lines[$rowLine]);
                    }

                    $names[] = $name->getLiteral();
                    $rowLine++;
                }
            }

            return $names;
        }

        throw new RuntimeException('docs/operations.md has no prerequisite table in the expected shape.');
    }
}
