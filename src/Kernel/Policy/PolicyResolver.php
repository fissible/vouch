<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use InvalidArgumentException;

final class PolicyResolver
{
    /**
     * @param list<PolicyDocument|null> $layers ordered least specific first:
     *                                          global, tenant, role, user
     */
    public function resolve(array $layers): PolicyDocument
    {
        $present = array_values(array_filter(
            $layers,
            static fn (?PolicyDocument $layer): bool => $layer instanceof PolicyDocument,
        ));

        if ($present === []) {
            throw new InvalidArgumentException('Resolution requires at least one policy layer.');
        }

        $mostSpecific = $present[count($present) - 1];

        return new PolicyDocument(
            requirement: $mostSpecific->requirement,
            posture: $this->strictestPosture($present),
        );
    }

    /**
     * @param non-empty-list<PolicyDocument> $layers
     */
    private function strictestPosture(array $layers): EnumerationPosture
    {
        $strictest = EnumerationPosture::Friendly;

        foreach ($layers as $layer) {
            if ($layer->posture->isAtLeastAsStrictAs($strictest)) {
                $strictest = $layer->posture;
            }
        }

        return $strictest;
    }
}
